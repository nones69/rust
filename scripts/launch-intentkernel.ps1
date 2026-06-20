#Requires -Version 5.1
<#
.SYNOPSIS
    One-click launcher: build (if needed), start ikrl-init + platform UI, open browser.

.EXAMPLE
    .\scripts\launch-intentkernel.ps1
    .\scripts\launch-intentkernel.ps1 -SkipBuild
    .\scripts\launch-intentkernel.ps1 -Port 5000
#>
param(
    [switch]$SkipBuild,
    [int]$Port = 5000,
    [switch]$WithPqc
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path $PSScriptRoot -Parent
$RustDir  = Join-Path $RepoRoot "rust"
$BinDir   = Join-Path $RustDir "target\release"
$Platform = Join-Path $RepoRoot "platform"

function Write-Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }

Write-Host @"

  IntentKernel — Windows Launcher
  Daemons + Control Surface + IP-Discrambler + CRASS bridge

"@ -ForegroundColor White

if (-not $SkipBuild) {
    Write-Step "Building Rust release binaries"
    Push-Location $RustDir
    if ($WithPqc) {
        & .\..\scripts\build-pqc.ps1
    } else {
        cargo build --release
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
    }
    Pop-Location
}

$initExe = Join-Path $BinDir "ikrl-init.exe"
if (-not (Test-Path $initExe)) {
    throw "ikrl-init.exe not found. Run without -SkipBuild or build manually."
}

Write-Step "Starting IntentKernel daemon stack (ikrl-init --with-ai --with-bridge)"
$initArgs = @(
    "--bin-dir", $BinDir,
    "--with-ai",
    "--with-bridge"
)
$initProc = Start-Process -FilePath $initExe -ArgumentList $initArgs -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 2

Write-Step "Ensuring platform dependencies"
Push-Location $Platform
python -m pip install -q -r requirements.txt 2>$null
Pop-Location

Write-Step "Starting IntentOS control surface on port $Port"
$env:PORT = "$Port"
$uiProc = Start-Process -FilePath "python" -ArgumentList "app.py" -WorkingDirectory $Platform -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 2

$url = "http://127.0.0.1:$Port"
Write-Step "Opening $url"
Start-Process $url

Write-Host @"

  Running:
    ikrl-init   PID $($initProc.Id)  (capd, intentd, leasebroker, eventscope, ikrl-ai, ikrl-bridge)
    IntentOS UI PID $($uiProc.Id)    $url

  API:
    GET  $url/api/daemons/health
    GET  $url/api/ip/lookup?ip=8.8.8.8

  Stop:
    Stop-Process -Id $($initProc.Id),$($uiProc.Id) -Force

"@ -ForegroundColor Green