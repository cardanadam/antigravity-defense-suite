import os
import uuid
import subprocess
import sys

def main():
    print("==================================================")
    print("🛡️ ANTIGRAVITY DEFENSE SUITE - INSTALLER")
    print("==================================================")
    
    # 1. Generate unique local Canary Token
    token = f"AG_CANARY_{uuid.uuid4().hex.upper()}_SECURE"
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    
    print(f"[*] Generating local secure token...")
    with open(env_path, "w", encoding="utf-8") as f:
        f.write(f"CANARY_TOKEN={token}\n")
    print(f"[*] Token generated and saved securely to .env (DO NOT SHARE!)")

    # 2. Build Rust Engine
    scanner_dir = os.path.join(os.path.dirname(__file__), "injection_scanner")
    print("\n[*] Compiling Rust Injection Scanner (Engine)...")
    if os.path.exists(scanner_dir):
        try:
            subprocess.run(["cargo", "build", "--release"], cwd=scanner_dir, check=True)
            print("[*] Rust Engine compiled successfully!")
        except subprocess.CalledProcessError:
            print("[!] Failed to compile Rust engine. Please ensure 'cargo' is installed.")
            sys.exit(1)
    else:
        print("[!] injection_scanner directory not found.")
        sys.exit(1)

    # 3. Build and install PyO3 Bindings
    guard_dir = os.path.join(os.path.dirname(__file__), "antigravity_guard")
    print("\n[*] Installing Python Native Bindings (antigravity_guard)...")
    if os.path.exists(guard_dir):
        try:
            # Create a virtual environment or just install locally
            # Using pip install . or maturin develop
            subprocess.run([sys.executable, "-m", "pip", "install", "maturin"], check=True)
            subprocess.run(["maturin", "develop", "--release"], cwd=guard_dir, check=True)
            print("[*] Python Bindings installed successfully!")
        except subprocess.CalledProcessError as e:
            print(f"[!] Failed to install python bindings: {e}")
            # Non fatal, we just warn
    else:
        print("[!] antigravity_guard directory not found.")
    
    print("\n==================================================")
    print("✅ INSTALLATION COMPLETE!")
    print("Your system is now protected by Antigravity Defense Suite.")
    print(f"Your unique Canary Token is: {token}")
    print("Place this token inside your SYSTEM_PROMPT.md to enable the Canary Trap.")
    print("==================================================")

if __name__ == "__main__":
    main()
