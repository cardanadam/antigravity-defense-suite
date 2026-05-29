use pyo3::prelude::*;
use pyo3::types::PyTuple;
use regex::Regex;

fn normalize_leetspeak(text: &str) -> String {
    text.replace('0', "o")
        .replace('1', "i")
        .replace('3', "e")
        .replace('4', "a")
        .replace('@', "a")
}

fn decode_base64(text: &str) -> String {
    let b64_re = Regex::new(r"(?i)([A-Za-z0-9+/]{20,}={0,2})").unwrap();
    let mut result = text.to_string();
    
    for cap in b64_re.captures_iter(text) {
        let b64_str = &cap[1];
        if let Ok(decoded_bytes) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64_str) {
            if let Ok(decoded_str) = String::from_utf8(decoded_bytes) {
                result = result.replace(b64_str, &decoded_str);
            }
        }
    }
    result
}

#[pyfunction]
fn preprocess(text: &str) -> PyResult<String> {
    let b64 = decode_base64(text);
    Ok(normalize_leetspeak(&b64))
}

#[pyfunction]
fn check_canary_leak(text: &str, tokens: Vec<String>) -> PyResult<(bool, String)> {
    for token in tokens {
        if text.contains(&token) {
            return Ok((true, token));
        }
    }
    Ok((false, String::new()))
}

#[pyfunction]
fn is_safe(text: &str) -> PyResult<bool> {
    let processed = preprocess(text)?;
    let patterns = vec![
        r"(?i)(ignore.*previous|unrestricted.*ai)",
        r"(?i)(dan\smode|developer\smode)",
        r"(?i)(delete.*logs|system\sadministrator)",
        r"(?i)(show.*system.*prompt|hidden.*instructions)",
        r"(?i)(\[SYSTEM\]|\[HIDDEN\])",
    ];

    for pattern in patterns {
        if let Ok(re) = Regex::new(pattern) {
            if re.is_match(&processed) || re.is_match(text) {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

#[pyfunction]
fn scan(py: Python, text: &str) -> PyResult<(bool, String, Vec<(String, f32, String)>)> {
    let mut matches = Vec::new();
    let processed = preprocess(text)?;
    let texts_to_scan = vec![text, &processed];

    let categories = vec![
        ("direct_injection", r"(?i)(ignore.*previous|unrestricted.*ai)"),
        ("jailbreak", r"(?i)(dan\smode|developer\smode)"),
        ("social_engineering", r"(?i)(delete.*logs|system\sadministrator)"),
        ("leakage", r"(?i)(show.*system.*prompt|hidden.*instructions)"),
    ];

    for t in texts_to_scan {
        for (cat, pattern) in &categories {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(t) {
                    matches.push((cat.to_string(), 1.0, t.chars().take(50).collect::<String>()));
                }
            }
        }
    }
    
    matches.dedup_by(|a, b| a.0 == b.0);

    let safe = matches.is_empty();
    let threat = if safe { "SAFE".to_string() } else { "HIGH".to_string() };

    Ok((safe, threat, matches))
}

#[pymodule]
fn antigravity_guard(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(preprocess, m)?)?;
    m.add_function(wrap_pyfunction!(check_canary_leak, m)?)?;
    m.add_function(wrap_pyfunction!(is_safe, m)?)?;
    m.add_function(wrap_pyfunction!(scan, m)?)?;
    Ok(())
}
