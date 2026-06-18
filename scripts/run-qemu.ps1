Write-Host "Starting QEMU..."
make run

if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}