param (
    [switch]$Clean = $false
)

if ($Clean) {
    Write-Host "Cleaning old output..."
    .\scripts\clean.ps1
}

Write-Host "Building project using Make..."
make

if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed!"
    exit $LASTEXITCODE
}

Write-Host "Verifying and copying artifacts to dist/..."
if (!(Test-Path "dist")) { New-Item -ItemType Directory -Force -Path "dist" | Out-Null }

# Update these paths as your build produces the actual kernel image or ISO
if (Test-Path "test_harness.exe") { 
    Copy-Item -Path "test_harness.exe" -Destination "dist\" -Force 
}