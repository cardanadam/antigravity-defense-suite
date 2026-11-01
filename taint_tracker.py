#!/usr/bin/env python3
"""
Taint Tracking Module (Untrusted Source Flow Guard)
Inspired by jev-guard's `from_untrusted` pattern.

Tracks data extracted from untrusted sources (web pages, downloaded files,
external API results, browser scraping) and flags when an agent attempts
to execute commands, URLs, or write payloads directly originating from
that untrusted content.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

# Universal benign commands that should never be tainted
SAFE_EXCLUSIONS = frozenset({
    "git status",
    "git log",
    "git diff",
    "git branch",
    "dir",
    "ls",
    "pwd",
    "cd",
    "whoami",
    "python --version",
    "python -v",
    "node -v",
    "npm -v",
    "cargo --version",
    "rustc --version",
})

# Patterns for extracting command snippets from untrusted text
_CODE_BLOCK_RE = re.compile(
    r"```(?:bash|sh|powershell|cmd|ps1|shell|python)?\s*\n(.*?)\n```",
    re.DOTALL | re.IGNORECASE,
)
_INLINE_CMD_RE = re.compile(r"`([^`\n]{4,120})`")
_DIRECTIVE_CMD_RE = re.compile(
    r"(?i)(?:run|execute|call|type|çalıştır|uygula|komut)\s*[:\-—]?\s*[`\"']?([a-z0-9_.\-\/\\]+\s+[^\n`\"']{3,100})[`\"']?"
)
_URL_RE = re.compile(r"https?://[^\s<>\"'`\(\)]+")


def _normalize(cmd: str) -> str:
    """Normalize whitespace and strip enclosing quotes."""
    s = (cmd or "").strip().strip("\"'`;")
    return " ".join(s.split()).lower()


@dataclass
class TaintEntry:
    source_tool: str
    normalized_value: str
    raw_snippet: str
    category: str  # "command" | "url" | "payload"


class TaintStore:
    """In-memory session store tracking untrusted payload items."""

    def __init__(self, max_items: int = 150) -> None:
        self.max_items = max_items
        self._entries: List[TaintEntry] = []
        self._normalized_set: Set[str] = set()

    def record_untrusted_text(self, source_tool: str, text: str) -> List[TaintEntry]:
        """Extract and record actionable instructions / commands / URLs from untrusted text."""
        if not text or not isinstance(text, str):
            return []

        extracted: List[TaintEntry] = []

        # 1. Extract from fenced code blocks
        for match in _CODE_BLOCK_RE.finditer(text):
            block = match.group(1).strip()
            for line in block.splitlines():
                clean_line = line.strip().lstrip("$># ").strip()
                if len(clean_line) >= 4 and not clean_line.startswith(("#", "//", "REM ")):
                    norm = _normalize(clean_line)
                    if norm and norm not in SAFE_EXCLUSIONS and norm not in self._normalized_set:
                        entry = TaintEntry(
                            source_tool=source_tool,
                            normalized_value=norm,
                            raw_snippet=clean_line[:100],
                            category="command",
                        )
                        extracted.append(entry)

        # 2. Extract from inline backticks
        for match in _INLINE_CMD_RE.finditer(text):
            inline = match.group(1).strip()
            norm = _normalize(inline)
            # Only taint if it looks like a shell command or URL
            is_cmd_like = any(
                norm.startswith(prefix)
                for prefix in (
                    "curl ", "wget ", "rm ", "del ", "git ", "npm ", "pip ", "python ",
                    "bash ", "powershell ", "sh ", "format ", "remove-item ", "set-content ",
                    "invoke-webrequest ", "irm ", "iwr ", "netsh ", "schtasks ", "systemctl ",
                )
            )
            if is_cmd_like and norm not in SAFE_EXCLUSIONS and norm not in self._normalized_set:
                entry = TaintEntry(
                    source_tool=source_tool,
                    normalized_value=norm,
                    raw_snippet=inline[:100],
                    category="command",
                )
                extracted.append(entry)

        # 3. Extract from explicit directive phrases ("run: ...", "çalıştır: ...")
        for match in _DIRECTIVE_CMD_RE.finditer(text):
            dir_cmd = match.group(1).strip()
            norm = _normalize(dir_cmd)
            if norm and norm not in SAFE_EXCLUSIONS and norm not in self._normalized_set:
                entry = TaintEntry(
                    source_tool=source_tool,
                    normalized_value=norm,
                    raw_snippet=dir_cmd[:100],
                    category="command",
                )
                extracted.append(entry)

        # 4. Extract external URLs
        for match in _URL_RE.finditer(text):
            url = match.group(0).rstrip(".,;!?:)")
            norm = url.lower()
            if len(norm) > 12 and norm not in self._normalized_set:
                entry = TaintEntry(
                    source_tool=source_tool,
                    normalized_value=norm,
                    raw_snippet=url[:100],
                    category="url",
                )
                extracted.append(entry)

        # Append to bounded store
        for e in extracted:
            self._entries.append(e)
            self._normalized_set.add(e.normalized_value)

        while len(self._entries) > self.max_items:
            oldest = self._entries.pop(0)
            self._normalized_set.discard(oldest.normalized_value)

        return extracted

    def check_taint(
        self, tool_name: str, args: Dict[str, Any] | Any
    ) -> Tuple[bool, Optional[TaintEntry]]:
        """
        Check if any argument in a proposed tool call matches a recorded untrusted payload.
        Returns (is_tainted, matching_entry).
        """
        if not self._entries:
            return False, None

        safe_args = args if isinstance(args, dict) else {"raw": str(args)}
        serialized = json.dumps(safe_args, ensure_ascii=False)
        serialized_norm = " ".join(serialized.lower().split())

        # Check explicit command field
        for key in ("command", "cmd", "script", "url", "target", "path", "content"):
            val = safe_args.get(key)
            if isinstance(val, str) and val.strip():
                val_norm = _normalize(val)
                for entry in self._entries:
                    if entry.normalized_value in val_norm or val_norm in entry.normalized_value:
                        return True, entry

        # Fallback check across serialized argument string
        for entry in self._entries:
            if entry.normalized_value in serialized_norm:
                return True, entry

        return False, None

    def clear(self) -> None:
        """Clear all active taint items."""
        self._entries.clear()
        self._normalized_set.clear()

    @property
    def count(self) -> int:
        return len(self._entries)


# Global default session taint store
_GLOBAL_TAINT_STORE = TaintStore()


def get_global_taint_store() -> TaintStore:
    return _GLOBAL_TAINT_STORE


def record_untrusted_data(source_tool: str, text: str) -> List[TaintEntry]:
    """Helper to record untrusted data into the global session store."""
    return _GLOBAL_TAINT_STORE.record_untrusted_text(source_tool, text)


def check_tool_call_taint(
    tool_name: str, args: Dict[str, Any] | Any
) -> Tuple[bool, Optional[TaintEntry]]:
    """Helper to check a tool call against the global session taint store."""
    return _GLOBAL_TAINT_STORE.check_taint(tool_name, args)


def clear_taint_store() -> None:
    """Helper to reset the global session taint store."""
    _GLOBAL_TAINT_STORE.clear()
