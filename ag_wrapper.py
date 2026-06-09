import antigravity_guard as ag
import json

def agent_tool_call_middleware(tool_name: str, arguments: dict) -> bool:
    """
    Middleware that intercepts any tool call made by the Antigravity Agent.
    Passes the arguments to the Rust-powered Defense Suite.
    """
    # Serialize arguments to string for semantic scanning
    payload = json.dumps(arguments, ensure_ascii=False)
    
    # Decrypt and normalize obfuscations (Rot13, Base64, Web Encoding)
    normalized_payload = ag.preprocess(payload) if hasattr(ag, 'preprocess') else payload
    
    # Scan with Rust engine
    # In older PyO3 bindings the signature might be just scan(text)
    try:
        is_safe, threat_level, matches = ag.scan(normalized_payload)
    except TypeError:
        # Fallback if signature doesn't match exactly
        is_safe, threat_level, matches = ag.scan(normalized_payload)
        
    if not is_safe:
        print(f"🚨 [DEFENSE SUITE BLOCK] Threat Level: {threat_level}")
        print(f"🚫 Blocked Tool: {tool_name}")
        print(f"🔍 Matches: {matches}")
        return False
        
    return True

# --- Simulation ---
if __name__ == "__main__":
    print("--- Testing Safe Tool Call ---")
    safe_args = {"query": "how to sort a list in python"}
    if agent_tool_call_middleware("search_web", safe_args):
        print("✅ Tool call allowed.\n")
        
    print("--- Testing Hijacked Tool Call ---")
    hijack_args = {"cmd": "rm -rf /*", "target": "format C:"}
    if not agent_tool_call_middleware("run_command", hijack_args):
        print("✅ Hijack successfully blocked.\n")
