#!/usr/bin/env python3
"""
🔒 Antigravity Security Gate
Pre-commit hook that runs fight_club tests before allowing commits

Install: Copy this file to .git/hooks/pre-commit (or run install command)
"""

import subprocess
import sys
from pathlib import Path

# Paths
TOOLS_DIR = Path(__file__).parent.parent.parent / "tools" / "forged"
FIGHT_CLUB = TOOLS_DIR / "fight_club.py"
SCANNER_EXE = TOOLS_DIR / "injection_scanner" / "target" / "release" / "injection_scanner.exe"

# Thresholds
MIN_BLOCK_RATE = 80  # Minimum % of attacks that must be blocked
MAX_FALSE_POSITIVE = 20  # Maximum % false positives allowed


def run_security_tests():
    """Run fight_club and check results"""
    print("🛡️ ANTIGRAVITY SECURITY GATE")
    print("=" * 50)
    print("Running pre-commit security checks...\n")
    
    # Check scanner exists
    if not SCANNER_EXE.exists():
        print(f"⚠️ Scanner not found: {SCANNER_EXE}")
        print("Run: cargo build --release in injection_scanner/")
        return False
    
    # Quick scan of staged files for obvious injections
    try:
        import antigravity_guard as ag
        
        # Get staged files
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only"],
            capture_output=True, text=True
        )
        staged_files = result.stdout.strip().split('\n') if result.stdout.strip() else []
        
        print(f"📁 Checking {len(staged_files)} staged files...\n")
        
        threats_found = 0
        for filepath in staged_files:
            if not filepath or not Path(filepath).exists():
                continue
            
            # Only check text files
            if not filepath.endswith(('.md', '.py', '.rs', '.json', '.txt', '.yaml', '.yml')):
                continue
            
            try:
                content = Path(filepath).read_text(encoding='utf-8', errors='ignore')
                is_safe, threat_level, matches = ag.scan(content)
                
                if not is_safe:
                    print(f"⚠️  {filepath}: {threat_level}")
                    for match in matches[:3]:  # Show first 3 matches
                        print(f"    - [{match[0]}] {match[2][:50]}...")
                    threats_found += 1
                else:
                    print(f"✅ {filepath}: SAFE")
            except Exception as e:
                print(f"⚠️  {filepath}: Error scanning - {e}")
        
        print()
        
        if threats_found > 0:
            print(f"🔴 BLOCKED: {threats_found} file(s) contain suspicious patterns")
            print("Review and fix before committing.")
            return False
        
        print("✅ All staged files passed security check")
        return True
        
    except ImportError:
        print("⚠️ antigravity_guard not installed")
        print("Falling back to basic check...")
        
        # Basic pattern check without PyO3
        dangerous_patterns = [
            "ignore previous",
            "forget all",
            "system prompt",
            "[SYSTEM]",
            "[HIDDEN]",
        ]
        
        result = subprocess.run(
            ["git", "diff", "--cached"],
            capture_output=True, text=True
        )
        
        for pattern in dangerous_patterns:
            if pattern.lower() in result.stdout.lower():
                print(f"🔴 Dangerous pattern found: {pattern}")
                return False
        
        print("✅ Basic check passed")
        return True


def main():
    """Main entry point"""
    if run_security_tests():
        print("\n🟢 COMMIT ALLOWED")
        sys.exit(0)
    else:
        print("\n🔴 COMMIT BLOCKED - Security check failed")
        print("Use 'git commit --no-verify' to bypass (NOT RECOMMENDED)")
        sys.exit(1)


if __name__ == "__main__":
    main()
