import os
import subprocess
import sys
import uuid


def main():
    print("==================================================")
    print("ANTIGRAVITY DEFENSE SUITE - INSTALLER")
    print("==================================================")

    # 1. Generate unique local Canary Token (only if .env does not exist)
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    if not os.path.exists(env_path):
        token = f"AG_CANARY_{uuid.uuid4().hex.upper()}_SECURE"
        print("[*] Generating local secure token...")
        with open(env_path, "w", encoding="utf-8") as f:
            f.write(f"CANARY_TOKEN={token}\n")
        print("[*] Token generated and saved to .env (not printed to console for security).")
    else:
        print("[*] Existing .env found; preserving current configuration.")

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
            subprocess.run([sys.executable, "-m", "pip", "install", "maturin"], check=True)
            subprocess.run(["maturin", "develop", "--release"], cwd=guard_dir, check=True)
            print("[*] Python Bindings installed successfully!")
        except subprocess.CalledProcessError as e:
            print(f"[!] Failed to install python bindings: {e}")
    else:
        print("[!] antigravity_guard directory not found.")

    print("\n==================================================")
    print("INSTALLATION COMPLETE!")
    print("Your local Canary Token is stored in .env (keep it private).")
    print("==================================================")


if __name__ == "__main__":
    main()
