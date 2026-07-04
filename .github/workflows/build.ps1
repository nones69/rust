param (
    [switch]$Clean = $false
)

if ($Clean) {
    Write-Host "Cleaning old output..."
    .\scripts\clean.ps1
}

if (!(Test-Path -Path "rust" -PathType Container)) {
    Write-Error "Rust workspace directory 'rust' was not found."
    exit 1
}

if (!(Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Error "cargo was not found on PATH."
    exit 1
}

Write-Host "Building primary Rust workspace..."
Push-Location "rust"
cargo build --release
$buildExitCode = $LASTEXITCODE
Pop-Location

if ($buildExitCode -ne 0) {
    Write-Error "Build failed!"
    exit $buildExitCode
}

Write-Host "Verifying Rust release artifacts..."
if (!(Test-Path "rust/target/release")) {
    Write-Error "Build output directory rust/target/release was not created."
    exit 1
}