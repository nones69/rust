#Requires -Version 5.1
<#
.SYNOPSIS
    Build IntentKernel with real PQC (liboqs via intentkernel-crypto/oqs feature).
    Falls back to mock crypto if liboqs is unavailable.
#>
$ErrorActionPreference = "Stop"
$RustDir = Join-Path (Split-Path $PSScriptRoot -Parent) "rust"
Push-Location $RustDir

Write-Host "Attempting PQC build (intentkernel-crypto --features oqs)..." -ForegroundColor Cyan
cargo build --release -p intentkernel-crypto --features oqs 2>&1 | Tee-Object -Variable pqcLog
if ($LASTEXITCODE -eq 0) {
    Write-Host "[OK] liboqs backend linked" -ForegroundColor Green
    cargo build --release
    if ($LASTEXITCODE -ne 0) { throw "full workspace build failed" }
    Pop-Location
    exit 0
}

Write-Host "[WARN] liboqs build failed — using mock PQC backend" -ForegroundColor Yellow
Write-Host $pqcLog -ForegroundColor DarkGray
cargo build --release
if ($LASTEXITCODE -ne 0) { throw "mock crypto build failed" }
Pop-Location
exit 0