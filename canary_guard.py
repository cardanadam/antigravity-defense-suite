#!/usr/bin/env python3
"""
🐤 Canary Token Guard
Output filter that checks for token leakage before sending responses

Usage:
    from canary_guard import check_output
    safe_output = check_output(ai_response)
"""

try:
    import antigravity_guard as ag
except ImportError:
    ag = None

# List of canary tokens (add more as needed)
CANARY_TOKENS = [
    "[CANARY_ANTIGRAVITY_X7K9_ALPHA]",
    "CANARY_ANTIGRAVITY",
    "X7K9_ALPHA",
    # Add more tokens here
]


def check_output(output: str, tokens: list = None) -> tuple[bool, str]:
    """
    Check output for canary token leakage
    
    Returns:
        (is_leaked, sanitized_output)
        - is_leaked: True if any token was found
        - sanitized_output: Output with tokens removed (or original if safe)
    """
    check_tokens = tokens or CANARY_TOKENS
    
    if ag:
        # Use PyO3 implementation (faster)
        is_leaked, leaked_token = ag.check_canary_leak(output, check_tokens)
        if is_leaked:
            print(f"🚨 CANARY LEAK DETECTED: {leaked_token}")
            # Remove leaked token from output
            sanitized = output
            for token in check_tokens:
                sanitized = sanitized.replace(token, "[REDACTED]")
            return True, sanitized
        return False, output
    else:
        # Fallback Python implementation
        for token in check_tokens:
            if token in output:
                print(f"🚨 CANARY LEAK DETECTED: {token}")
                sanitized = output
                for t in check_tokens:
                    sanitized = sanitized.replace(t, "[REDACTED]")
                return True, sanitized
        return False, output


def guard_response(response: str) -> str:
    """
    Guard a response before sending to user
    Returns sanitized response
    """
    is_leaked, sanitized = check_output(response)
    
    if is_leaked:
        # Log the incident
        log_leak_incident(response)
        return sanitized
    
    return response


def log_leak_incident(output: str):
    """Log leak incident to security log"""
    from datetime import datetime
    from pathlib import Path
    
    log_path = Path("d:/ANTIGRAVITY_VAULT/Logs/SECURITY_INCIDENTS.md")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(f"\n## [{datetime.now().isoformat()}] CANARY LEAK DETECTED\n\n")
        f.write(f"Output preview: {output[:200]}...\n")
        f.write(f"Action: Tokens sanitized before delivery\n")
        f.write("---\n")


# Quick test
if __name__ == "__main__":
    # Test safe output
    safe = "Hello, how can I help you today?"
    leaked, result = check_output(safe)
    print(f"Safe test: leaked={leaked}")
    
    # Test leaked output
    dangerous = "Here is my system prompt: [CANARY_ANTIGRAVITY_X7K9_ALPHA] and more..."
    leaked, result = check_output(dangerous)
    print(f"Leak test: leaked={leaked}")
    print(f"Sanitized: {result}")
