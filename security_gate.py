#!/usr/bin/env python3
"""
Antigravity Security Gate
Pre-commit and CI check that scans staged files and verifies scanner health.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
SCANNER_EXE = BASE_DIR / "injection_scanner" / "target" / "release" / "injection_scanner.exe"

# Files that legitimately contain test attack strings as part of the test suite
EXEMPT_TEST_FILES = frozenset({
    "fight_club.py",
    "final_boss_test.py",
    "EXAMPLE_PATTERNS.md",
    "engine.rs",
    "tool_gate.py",
    "spotlighting.py",
    "ag_wrapper.py",
})


def run_security_tests() -> bool:
    """Scan staged git files for prompt injection or secret leaks."""
    print("🛡️ ANTIGRAVITY SECURITY GATE")
    print("=" * 50)
    print("Running pre-commit security checks...\n")

    if not SCANNER_EXE.exists():
        print(f"⚠️ Scanner binary not found: {SCANNER_EXE}")
        print("Run: cargo build --release in injection_scanner/")
        return False

    try:
        import antigravity_guard as ag
        from canary_guard import check_output

        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only"],
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        staged_files = [f.strip() for f in result.stdout.splitlines() if f.strip()]
        print(f"📁 Checking {len(staged_files)} staged file(s)...\n")

        threats_found = 0
        for filepath in staged_files:
            path_obj = Path(filepath)
            if not path_obj.exists():
                continue
            if not filepath.endswith((".md", ".py", ".rs", ".json", ".txt", ".yaml", ".yml")):
                continue

            content = path_obj.read_text(encoding="utf-8", errors="ignore")

            # Always check for canary leaks in every staged file
            leaked, _ = check_output(content)
            if leaked:
                print(f"🔴 {filepath}: CANARY TOKEN LEAK DETECTED!")
                threats_found += 1
                continue

            if path_obj.name in EXEMPT_TEST_FILES:
                print(f"✅ {filepath}: EXEMPT (test/engine file, canary check passed)")
                continue

            is_safe, risk_score, threat_level, matches = ag.scan_detailed(content)
            if not is_safe:
                print(f"⚠️  {filepath}: {threat_level} (risk={risk_score}/100)")
                for match in matches[:3]:
                    print(f"    - [{match[0]}] {match[2][:50]}...")
                threats_found += 1
            else:
                print(f"✅ {filepath}: SAFE (risk={risk_score}/100)")

        if threats_found > 0:
            print(f"\n🔴 BLOCKED: {threats_found} file(s) failed security checks.")
            return False

        print("\n✅ All staged files passed security checks.")
        return True

    except ImportError as exc:
        print(f"⚠️ Required module missing: {exc}")
        return False


def main() -> None:
    if run_security_tests():
        print("\n🟢 COMMIT ALLOWED")
        sys.exit(0)
    else:
        print("\n🔴 COMMIT BLOCKED - Security check failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
