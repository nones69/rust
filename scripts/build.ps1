#Requires -Version 5.1

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path $PSScriptRoot -Parent
$RustDir = Join-Path $RepoRoot "rust"

Write-Host "Building primary Rust package..."
Push-Location $RustDir

try {
    cargo build --release -p intentos
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
} finally {
    Pop-Location
}
