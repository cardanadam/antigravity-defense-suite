#!/usr/bin/env python3
"""
Intent Alignment Guard
Inspects the user's explicit request against the agent's planned tool call / command.

Flags actions where an agent attempts destructive, exfiltrating, or high-impact
system modifications that have no corresponding intent in the user's prompt.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Tuple

# Patterns identifying destructive actions in tools/commands
_DESTRUCTIVE_TOOL_RE = re.compile(
    r"(?is)("
    r"\b(?:Remove-Item|ri|del|erase|rd|rmdir|unlink|rm)\b|"
    r"\bshutil\.rmtree\b|"
    r"\bos\.(?:remove|unlink|rmdir)\b|"
    r"\bgit\s+(?:reset\s+--hard|clean\s+-[a-zA-Z]*f|branch\s+-[a-zA-Z]*D)\b|"
    r"\b(?:format|diskpart|bcdedit|kill|taskkill)\b"
    r")"
)

# Patterns identifying outbound exfiltration or upload
_EXFIL_TOOL_RE = re.compile(
    r"(?is)("
    r"\bcurl\b[^\n]*(?:-X\s*POST|--data|-d\s|-F\s|--upload-file)|"
    r"\b(?:Invoke-RestMethod|Invoke-WebRequest|irm|iwr)\b[^\n]*-Method\s+(?:Post|Put)|"
    r"\bwget\b[^\n]*--post-(?:data|file)|"
    r"\b(?:requests|httpx)\.(?:post|put)\b|"
    r"\b(?:webhook\.site|pastebin\.com|transfer\.sh|evil\.com)\b"
    r")"
)

# Patterns identifying scheduled task or cron modification
_SCHEDULE_TOOL_RE = re.compile(
    r"(?is)("
    r"\bschtasks(?:\.exe)?\s+[^\n;|&]*\/(?:create|change|delete|run)\b|"
    r"\b(?:Register-ScheduledTask|Set-ScheduledTask|Unregister-ScheduledTask)\b|"
    r"\bcrontab\s+-[a-zA-Z]*[er]\b"
    r")"
)

# Patterns identifying security configuration modification
_SECURITY_CONFIG_TOOL_RE = re.compile(
    r"(?is)("
    r"\bSet-MpPreference\b|"
    r"\bnetsh\s+advfirewall\b|"
    r"\bDisable-NetFirewallRule\b|"
    r"\bStop-Service\b[^\n;|&]*(?:windefend|mpssvc)"
    r")"
)

# User intent keywords for destruction / removal
_USER_DESTRUCTIVE_INTENT_RE = re.compile(
    r"(?is)\b("
    r"sil(?:in|iniz|me|insin|insinler|er misin|ebilir misin|)?|"
    r"kaldir(?:in|iniz|ma|ilsin)?|"
    r"temizle(?:yin|yiniz|me|nsin)?|"
    r"yok\s*et|"
    r"delete|"
    r"remove|"
    r"erase|"
    r"drop|"
    r"clean|"
    r"purge|"
    r"wipe|"
    r"destroy|"
    r"uninstall|"
    r"reset"
    r")\b"
)

# User intent keywords for sharing / sending data outward
_USER_SEND_INTENT_RE = re.compile(
    r"(?is)\b("
    r"gonder(?:in|iniz|me)?|"
    r"ilet(?:in|iniz)?|"
    r"yukle(?:yin|yiniz)?|"
    r"paylas(?:in|iniz)?|"
    r"send|"
    r"post|"
    r"upload|"
    r"publish|"
    r"share|"
    r"webhook|"
    r"transmit"
    r")\b"
)

# User intent keywords for scheduling / cron jobs
_USER_SCHEDULE_INTENT_RE = re.compile(
    r"(?is)\b("
    r"zamanla(?:yin|yiniz)?|"
    r"zamanlanmis\s+gorev|"
    r"her\s+(?:gun|saat|hafta|dakika)|"
    r"schedule|"
    r"cron|"
    r"recurring|"
    r"timer|"
    r"periyodik"
    r")\b"
)

# User intent keywords for security configuration
_USER_SECURITY_INTENT_RE = re.compile(
    r"(?is)\b("
    r"guvenlik\s+duvari|"
    r"defender|"
    r"antivirus|"
    r"firewall|"
    r"guvenlik\s+ayari"
    r")\b"
)


def evaluate_intent_alignment(
    user_prompt: Optional[str],
    tool_name: str,
    args: Dict[str, Any] | Any,
) -> Tuple[bool, str, str]:
    """
    Evaluates whether the proposed tool call aligns with the user's prompt.
    Returns: (is_aligned, recommended_action, reason)
      - is_aligned: bool
      - recommended_action: "allow" | "approve" | "block"
      - reason: str
    """
    if not user_prompt or not isinstance(user_prompt, str) or not user_prompt.strip():
        # Without prompt context, cannot determine mismatch
        return True, "allow", "No user prompt provided for intent alignment"

    safe_args = args if isinstance(args, dict) else {"raw": str(args)}
    serialized = json.dumps(safe_args, ensure_ascii=False)
    norm_prompt = user_prompt.strip()

    # 1. Check Destructive Tool Call Mismatch
    if _DESTRUCTIVE_TOOL_RE.search(serialized) or tool_name in {"delete_file", "remove_file"}:
        has_destruct_intent = bool(_USER_DESTRUCTIVE_INTENT_RE.search(norm_prompt))
        if not has_destruct_intent:
            return (
                False,
                "approve",
                (
                    f"Intent mismatch: Tool '{tool_name}' performs destructive deletion/reset, "
                    f"but user prompt contains no deletion/cleanup intent ('{norm_prompt[:60]}...')."
                ),
            )

    # 2. Check Outbound Exfiltration / External POST Mismatch
    if _EXFIL_TOOL_RE.search(serialized):
        has_send_intent = bool(_USER_SEND_INTENT_RE.search(norm_prompt))
        if not has_send_intent:
            return (
                False,
                "approve",
                (
                    f"Intent mismatch: Tool '{tool_name}' transmits data to an external endpoint, "
                    f"but user prompt contains no sharing/upload intent."
                ),
            )

    # 3. Check Scheduled Task Creation Mismatch
    if _SCHEDULE_TOOL_RE.search(serialized):
        has_sched_intent = bool(_USER_SCHEDULE_INTENT_RE.search(norm_prompt))
        if not has_sched_intent:
            return (
                False,
                "approve",
                (
                    f"Intent mismatch: Tool '{tool_name}' creates/alters a scheduled task, "
                    f"but user prompt requested no scheduling or recurring automation."
                ),
            )

    # 4. Check Security Software Configuration Mismatch
    if _SECURITY_CONFIG_TOOL_RE.search(serialized):
        has_sec_intent = bool(_USER_SECURITY_INTENT_RE.search(norm_prompt))
        if not has_sec_intent:
            return (
                False,
                "block",
                (
                    f"Intent mismatch: Tool '{tool_name}' alters security software or firewall, "
                    f"which was not requested by the user."
                ),
            )

    return True, "allow", "Tool call aligns with user intent"
