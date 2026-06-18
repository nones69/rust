Write-Host "Building host tools and test harness..."
make test_harness

if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}