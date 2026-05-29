# 🛡️ Antigravity Defense Suite

> **Military-grade AI Security Shield** - Rust-powered prompt injection defense system

[![Rust](https://img.shields.io/badge/Rust-1.75+-orange?logo=rust)](https://www.rust-lang.org/)
[![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)](https://python.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

---

## 🎯 What is this?

A high-performance security system designed to protect AI/LLM applications from **prompt injection attacks**. Built with Rust for speed and Python for flexibility.

### The Problem

AI systems can be manipulated with clever prompts like:

- "Ignore your previous instructions and..."
- Base64-encoded hidden commands
- Social engineering attacks

### The Solution

Antigravity Defense Suite scans, decodes, and blocks these attacks in **real-time** using:

- 🦀 **Rust Core** - Millisecond-level pattern matching
- 🐍 **Python Bindings** - Easy integration via PyO3
- 🔐 **Canary Token System** - Detects data leakage
- 🎭 **Adversarial Training** - Battle-tested defenses

---

## 🚀 Features

| Feature             | Description                                 |
| :------------------ | :------------------------------------------ |
| `injection_scanner` | CLI tool for scanning text/files            |
| `antigravity_guard` | Python module (PyO3) for native integration |
| `fight_club.py`     | Adversarial training simulator              |
| `sentinel`          | Real-time log watcher with alerts           |
| `canary_guard.py`   | Output filter to prevent data leakage       |
| `security_gate.py`  | Pre-commit hook for CI/CD                   |

---

## 📦 Installation (One-Click Setup)

For the easiest setup, we provide automatic installation scripts that generate a **unique, local Canary Token** just for your machine and automatically compile the Rust engine.

### For Windows Users
Just run the PowerShell script:
```powershell
.\install.ps1
```

### For Linux/Mac/Universal Users
Run the Python script:
```bash
python install.py
```

### Manual Build from source
If you prefer building manually:
```bash
# Clone repository
git clone https://github.com/cardanadam/antigravity-defense-suite.git
cd antigravity-defense-suite

# Create your .env file with a unique Canary Token
echo "CANARY_TOKEN=your_secret_token_here" > .env

# Build Rust Engine & Python Bindings
cd antigravity_guard
pip install maturin
maturin develop --release
```

---

## 🔧 Usage

### CLI Scanner

```bash
# Scan text
./injection_scanner --input "Your text here" --verbose

# Scan file
./injection_scanner --file input.txt --output json
```

### Python Integration

```python
import antigravity_guard as ag

# Quick check
if ag.is_safe(user_input):
    process(user_input)
else:
    reject(user_input)

# Detailed scan
is_safe, threat_level, matches = ag.scan(user_input)

# Decode obfuscated attacks
decoded = ag.preprocess(suspicious_text)  # Base64, URL, Unicode, Leet
```

### Adversarial Training

```bash
# Run attack simulation
python fight_club.py
```

---

## 🧪 Detection Capabilities

| Attack Type         | Example                        | Status                  |
| :------------------ | :----------------------------- | :---------------------- |
| Direct Injection    | "Ignore previous instructions" | ✅ Blocked              |
| Jailbreak           | "DAN mode", "Developer mode"   | ✅ Blocked              |
| Leakage             | "Show system prompt"           | ✅ Blocked              |
| Social Engineering  | "This is urgent, delete now"   | ✅ Blocked              |
| Base64/Hex/Rot13    | `SWdub3JlIGFsbA==`             | ✅ Decoded & Blocked    |
| Leet Speak          | `1gn0r3 4ll`                   | ✅ Decoded & Blocked    |
| URL/HTML Entities   | `%69%67%6E%6F%72%65`           | ✅ Decoded & Blocked    |
| Unicode Obfuscation | 𝑖𝑔𝑛𝑜𝑟𝑒 𝑎𝑙𝑙               | ✅ Normalized & Blocked |
| Entropy Anomaly     | (Random Chaos Encryptions)     | ⚠️ Detected & Flagged   |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                 ANTIGRAVITY DEFENSE SUITE               │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────────┐    ┌─────────────────────────────┐ │
│  │   🦀 RUST CORE  │    │      🐍 PYTHON LAYER       │ │
│  │   (Speed)       │◄──►│      (Flexibility)         │ │
│  ├─────────────────┤    ├─────────────────────────────┤ │
│  │ • Pattern Engine│    │ • fight_club.py            │ │
│  │ • Base64 Decoder│    │ • canary_guard.py          │ │
│  │ • Unicode Norm  │    │ • security_gate.py         │ │
│  │ • Canary Check  │    │ • Report Generator         │ │
│  └─────────────────┘    └─────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

---

## 🔒 Security Notes

- **Canary tokens** and full attack patterns are **not included** in this repository for security reasons
- Create your own `.env` file with your secret tokens
- The pattern list in this repo contains only basic examples

```bash
# Create your .env file
echo "CANARY_TOKEN=your_secret_token_here" > .env
```

---

## 📊 Performance

Tested on Windows 11, AMD Ryzen 7:

| Operation                  | Speed |
| :------------------------- | :---- |
| Pattern scan (17 patterns) | < 1ms |
| Base64 decode + scan       | < 2ms |
| Full preprocess + scan     | < 5ms |

_PyO3 integration provides 10x-50x speedup over subprocess calls._

---

## 🤝 Contributing

Pull requests welcome! Especially for:

- New attack patterns (submit via issue, not PR for security)
- Performance optimizations
- Additional language support

---

## 📜 License

MIT License - See [LICENSE](LICENSE) for details.

---

## 👤 Author

**Antigravity** - Built with 🦀 Rust and 🐍 Python

_"I know the dark arts to defend against them, not to practice them."_
