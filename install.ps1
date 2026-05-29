Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "🛡️ ANTIGRAVITY DEFENSE SUITE - WINDOWS INSTALLER" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# 1. Generate unique Canary Token
$guid = [guid]::NewGuid().ToString("N").ToUpper()
$token = "AG_CANARY_${guid}_SECURE"
$envPath = Join-Path $PSScriptRoot ".env"

Write-Host "[*] Generating local secure token..." -ForegroundColor Yellow
Set-Content -Path $envPath -Value "CANARY_TOKEN=$token" -Encoding UTF8
Write-Host "[*] Token generated and saved securely to .env (DO NOT SHARE!)" -ForegroundColor Green

# 2. Compile Rust Scanner
$scannerDir = Join-Path $PSScriptRoot "injection_scanner"
Write-Host "`n[*] Compiling Rust Injection Scanner (Engine)..." -ForegroundColor Yellow
if (Test-Path $scannerDir) {
    Push-Location $scannerDir
    try {
        cargo build --release
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[*] Rust Engine compiled successfully!" -ForegroundColor Green
        } else {
            Write-Host "[!] Failed to compile Rust engine. Please ensure 'cargo' is installed." -ForegroundColor Red
        }
    } catch {
        Write-Host "[!] Cargo not found or failed to run." -ForegroundColor Red
    }
    Pop-Location
} else {
    Write-Host "[!] injection_scanner directory not found." -ForegroundColor Red
}

# 3. Compile Python Bindings (PyO3)
$guardDir = Join-Path $PSScriptRoot "antigravity_guard"
Write-Host "`n[*] Installing Python Native Bindings (antigravity_guard)..." -ForegroundColor Yellow
if (Test-Path $guardDir) {
    Push-Location $guardDir
    try {
        python -m pip install maturin
        maturin develop --release
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[*] Python Bindings installed successfully!" -ForegroundColor Green
        } else {
            Write-Host "[!] Failed to compile python bindings." -ForegroundColor Red
        }
    } catch {
        Write-Host "[!] Failed to run python or maturin." -ForegroundColor Red
    }
    Pop-Location
} else {
    Write-Host "[!] antigravity_guard directory not found." -ForegroundColor Red
}

Write-Host "`n==================================================" -ForegroundColor Cyan
Write-Host "✅ INSTALLATION COMPLETE!" -ForegroundColor Green
Write-Host "Your system is now protected by Antigravity Defense Suite."
Write-Host "Your unique Canary Token is: $token" -ForegroundColor Magenta
Write-Host "Place this token inside your SYSTEM_PROMPT.md to enable the Canary Trap."
Write-Host "==================================================" -ForegroundColor Cyan

Write-Host "`nPress any key to exit..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
