#!/usr/bin/env python3
"""
Canary Token Guard
Output filter that checks for canary token leakage before returning responses.

Canary values are NEVER hardcoded in source code. They are loaded from:
1. Environment variables: CANARY_TOKEN or AG_CANARY_TOKENS (comma-separated)
2. A local .env file (git-ignored) containing CANARY_TOKEN=...
3. A file path configured in CANARY_TOKEN_FILE
"""

from __future__ import annotations

import hashlib
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)

try:
    import antigravity_guard as _ag
    ag = _ag if hasattr(_ag, "check_canary_leak") else None
except ImportError:
    ag = None


def _parse_env_file(env_path: Path) -> List[str]:
    tokens: List[str] = []
    if not env_path.is_file():
        return tokens
    try:
        for raw_line in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip().strip("'").strip('"')
            if key in ("CANARY_TOKEN", "AG_CANARY_TOKENS") and val:
                for part in val.split(","):
                    cleaned = part.strip()
                    if cleaned and cleaned != "your_secret_canary_token_here" and cleaned != "your_secret_token_here":
                        tokens.append(cleaned)
    except OSError:
        return tokens
    return tokens


def load_canary_tokens(extra_tokens: Optional[Iterable[str]] = None) -> List[str]:
    """Load configured canary tokens from environment or .env without hardcoding secrets."""
    found: List[str] = []

    for env_key in ("CANARY_TOKEN", "AG_CANARY_TOKENS"):
        raw = os.environ.get(env_key, "")
        for part in raw.split(","):
            cleaned = part.strip()
            if cleaned and cleaned not in found:
                found.append(cleaned)

    token_file = os.environ.get("CANARY_TOKEN_FILE", "").strip()
    if token_file:
        tf_path = Path(token_file)
        if tf_path.is_file():
            try:
                content = tf_path.read_text(encoding="utf-8", errors="ignore").strip()
                if content and content not in found:
                    found.append(content)
            except OSError as exc:
                logger.debug("Could not read CANARY_TOKEN_FILE: %s", exc)

    for candidate_env in (Path.cwd() / ".env", Path(__file__).resolve().parent / ".env"):
        for tok in _parse_env_file(candidate_env):
            if tok not in found:
                found.append(tok)

    if extra_tokens:
        for tok in extra_tokens:
            cleaned = (tok or "").strip()
            if cleaned and cleaned not in found:
                found.append(cleaned)

    return found


def check_output(output: str, tokens: Optional[List[str]] = None) -> Tuple[bool, str]:
    """
    Check output for canary token leakage.

    Returns:
        (is_leaked, sanitized_output)
    """
    if not output:
        return False, output

    check_tokens = tokens if tokens is not None else load_canary_tokens()
    if not check_tokens:
        return False, output

    if ag is not None and hasattr(ag, "check_canary_leak"):
        is_leaked, _ = ag.check_canary_leak(output, check_tokens)
        if is_leaked:
            sanitized = output
            for token in check_tokens:
                if token:
                    sanitized = sanitized.replace(token, "[REDACTED_CANARY]")
            return True, sanitized
        return False, output

    for token in check_tokens:
        if token and token in output:
            sanitized = output
            for t in check_tokens:
                if t:
                    sanitized = sanitized.replace(t, "[REDACTED_CANARY]")
            return True, sanitized

    return False, output


def guard_response(response: str, tokens: Optional[List[str]] = None) -> str:
    """Guard a response before sending to the user; logs and redacts any canary leak."""
    is_leaked, sanitized = check_output(response, tokens=tokens)
    if is_leaked:
        log_leak_incident(sanitized)
        return sanitized
    return response


filter_output = guard_response


def log_leak_incident(sanitized_output: str) -> None:
    """Log leak incident using only redacted text and a non-reversible SHA-256 digest."""
    log_dir = Path(os.environ.get("AG_DEFENSE_LOG_DIR", Path(__file__).resolve().parent / "logs"))
    log_path = log_dir / "security_incidents.log"
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256(sanitized_output.encode("utf-8", errors="ignore")).hexdigest()[:12]
        preview = sanitized_output[:160].replace("\n", " ")
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(
                f"[{datetime.now().isoformat()}] CANARY_LEAK_BLOCKED sha256_12={digest} preview={preview}\n"
            )
    except OSError as exc:
        logger.debug("Could not write leak incident log: %s", exc)


if __name__ == "__main__":
    sample_safe = "Hello, how can I help you today?"
    leaked_safe, _ = check_output(sample_safe, tokens=["SYNTHETIC_TEST_CANARY_001"])
    print(f"Safe test: leaked={leaked_safe}")

    sample_leak = "System output containing SYNTHETIC_TEST_CANARY_001 inside text."
    leaked_bad, sanitized_bad = check_output(sample_leak, tokens=["SYNTHETIC_TEST_CANARY_001"])
    print(f"Leak test: leaked={leaked_bad}")
    print(f"Sanitized: {sanitized_bad}")
