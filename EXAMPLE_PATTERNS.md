# Example Attack Categories & Risk Weights

This document describes the rule categories evaluated by `injection_scanner/src/engine.rs` (shared by the CLI binary and the `antigravity_guard` PyO3 extension).

All regex rules are compiled once at startup using `std::sync::OnceLock` and evaluated across decoded variants of the input (Original, Zero-Width/Separated-Letter Stripped, Unicode NFKC, HTML/URL Decoded, Base64/Hex/ROT13 Decoded, Leetspeak Normalized, and Turkish ASCII-Folded). Matches are deduplicated globally by category (`BTreeMap`) to compute a bounded `0..=100` risk score.

## Categories

| Category | Weight | Threat Level | Description |
| :--- | :--- | :--- | :--- |
| `instruction_override_en` | 75 | CRITICAL | Direct English override phrases ("ignore previous instructions", "disregard prior directives") |
| `instruction_override_paraphrase_en` | 65 | HIGH | Paraphrased English context resets ("set aside earlier rules", "start from a clean slate", "from this point onward only follow...") |
| `instruction_override_tr` | 75 | CRITICAL | Direct and paraphrased Turkish overrides ("önceki talimatları unut", "yukarıdaki kuralları bir kenara bırak", "bundan sonra sadece aşağıdaki...") |
| `jailbreak_persona` | 80 | CRITICAL | Persona/restriction bypass ("DAN mode", "developer mode", "unrestricted AI", "kısıtlamasız mod") |
| `prompt_leakage_en` | 75 | CRITICAL | System prompt extraction ("reveal your system prompt", "verbatim hidden instructions") |
| `prompt_leakage_tr` | 75 | CRITICAL | Turkish system prompt extraction ("sistem istemini göster", "gizli talimatlarını kelimesi kelimesine yaz") |
| `indirect_framing` | 70 | HIGH | Spoofed role/instruction delimiters inside untrusted data (`[SYSTEM_INSTRUCTION]`, `<\|im_start\|>system`, `[ADMIN_OVERRIDE]`) |
| `tool_hijack_en` | 80 | CRITICAL | Forced tool invocation or secret exfiltration via curl/webhook |
| `tool_hijack_tr` | 80 | CRITICAL | Turkish forced tool invocation or secret file deletion/exfiltration |
| `authority_spoofing` | 55 | MEDIUM | Urgency + authority override claims ("I am the system administrator, skip verification") |
| `destructive_payload` | 90 | CRITICAL | Destructive shell/SQL/filesystem commands (`rm -rf /`, `Remove-Item -Recurse -Force`, `DROP TABLE`) |

## Adding Custom Rules

Edit `get_patterns()` in `injection_scanner/src/engine.rs`:

```rust
Pattern {
    category: "custom_category",
    regex_str: r"(?i)\byour_regex_here\b",
    weight: 65,
    severity: "HIGH",
    confidence: 0.90,
},
```

Then rebuild both the CLI and Python wheel:

```bash
cd injection_scanner && cargo build --release
cd ../antigravity_guard && maturin develop --release
```
