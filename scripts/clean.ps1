Write-Host "Cleaning build directories..."

$directories = @("out", "dist", "build")

foreach ($dir in $directories) {
    if (Test-Path $dir) {
        Remove-Item -Recurse -Force $dir
        Write-Host "Removed $dir/"
    }
}

make clean
Write-Host "Clean complete."