param (
    [switch]$Clean = $false
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path $PSScriptRoot -Parent
$RustDir = Join-Path $RepoRoot "rust"

if ($Clean) {
    Write-Host "Cleaning old output..."
    & (Join-Path $PSScriptRoot "clean.ps1")
}

Write-Host "Building primary Rust runtime..."
Push-Location $RustDir
try {
    cargo build --release -p intentos
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Build failed!"
        exit $LASTEXITCODE
    }
}
finally {
    Pop-Location
}

Write-Host "Verifying and copying artifacts to dist/..."
if (!(Test-Path (Join-Path $RepoRoot "dist"))) { New-Item -ItemType Directory -Force -Path (Join-Path $RepoRoot "dist") | Out-Null }

$IntentosBinary = Join-Path $RustDir "target\release\intentos.exe"
if (!(Test-Path $IntentosBinary)) {
    $IntentosBinary = Join-Path $RustDir "target\release\intentos"
}

if (Test-Path $IntentosBinary) {
    Copy-Item -Path $IntentosBinary -Destination (Join-Path $RepoRoot "dist\") -Force
}