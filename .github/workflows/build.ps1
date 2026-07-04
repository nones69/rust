param (
    [switch]$Clean = $false
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path $PSScriptRoot -Parent | Split-Path -Parent
$RustDir = Join-Path $RepoRoot "rust"

if ($Clean) {
    Write-Host "Cleaning old output..."
    & (Join-Path $RepoRoot "scripts/clean.ps1")
}

Write-Host "Building primary Rust package..."
Push-Location $RustDir
try {
    cargo build --release -p intentos
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Build failed!"
        exit $LASTEXITCODE
    }
} finally {
    Pop-Location
}