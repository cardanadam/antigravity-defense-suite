use pyo3::prelude::*;

#[path = "../../injection_scanner/src/engine.rs"]
mod engine;

#[pyfunction]
fn preprocess(text: &str) -> PyResult<String> {
    Ok(engine::Engine::preprocess(text))
}

#[pyfunction]
fn check_canary_leak(text: &str, tokens: Vec<String>) -> PyResult<(bool, String)> {
    for token in tokens {
        if !token.is_empty() && text.contains(&token) {
            return Ok((true, token));
        }
    }
    Ok((false, String::new()))
}

#[pyfunction]
fn is_safe(text: &str) -> PyResult<bool> {
    let scanner = engine::Engine::new();
    Ok(scanner.scan(text).is_safe)
}

#[pyfunction]
fn risk_score(text: &str) -> PyResult<u8> {
    let scanner = engine::Engine::new();
    Ok(scanner.scan(text).risk_score)
}

#[pyfunction]
fn scan(text: &str) -> PyResult<(bool, String, Vec<(String, f32, String)>)> {
    let scanner = engine::Engine::new();
    let res = scanner.scan(text);
    Ok((res.is_safe, res.threat_level, res.matches))
}

#[pyfunction]
fn scan_detailed(text: &str) -> PyResult<(bool, u8, String, Vec<(String, f32, String)>)> {
    let scanner = engine::Engine::new();
    let res = scanner.scan(text);
    Ok((res.is_safe, res.risk_score, res.threat_level, res.matches))
}

#[pymodule]
fn antigravity_guard(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(preprocess, m)?)?;
    m.add_function(wrap_pyfunction!(check_canary_leak, m)?)?;
    m.add_function(wrap_pyfunction!(is_safe, m)?)?;
    m.add_function(wrap_pyfunction!(risk_score, m)?)?;
    m.add_function(wrap_pyfunction!(scan, m)?)?;
    m.add_function(wrap_pyfunction!(scan_detailed, m)?)?;
    Ok(())
}
