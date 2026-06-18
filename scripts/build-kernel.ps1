Write-Host "Building IntentKernel..."
make kernel

if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}