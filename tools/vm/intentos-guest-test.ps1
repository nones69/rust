#Requires -Version 5.1
<#
.SYNOPSIS
  Run inside a Windows VM guest — smoke-test IntentOS with isolated state.
#>
param(
    [string]$Binary = ".\intentos.exe",
    [string]$StateDir = "$env:TEMP\intentos-vm-guest"
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path $Binary)) {
    Write-Error "Binary not found: $Binary"
}

New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
$env:INTENTOS_STATE_DIR = $StateDir
$env:INTENTOS_SKIP_OOBE = "1"

$cmds = @("1", "2", "3", "broker status", "kernel stats", "audit verify", "flow file read")
$fail = 0
foreach ($c in $cmds) {
    Write-Host ">> $c" -ForegroundColor Cyan
    & $Binary -c $c 2>&1 | Out-Host
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[FAIL] $c (exit $LASTEXITCODE)" -ForegroundColor Red
        $fail++
    } else {
        Write-Host "[PASS] $c" -ForegroundColor Green
    }
}

if ($fail -gt 0) {
    Write-Host "Guest test failed: $fail command(s)" -ForegroundColor Red
    exit 1
}
Write-Host "Guest VM test passed — state at $StateDir" -ForegroundColor Green