#Requires -Version 5.1
<#
.SYNOPSIS
  Validate IntentOS in an isolated sandbox (mimics a fresh VM) or inside a Hyper-V VM.

.DESCRIPTION
  Phase 1 — Sandbox (no VM required):
    - Creates a temp INTENTOS_STATE_DIR (clean profile, no host pollution)
    - Builds release binary
    - Runs shell command smoke tests
    - Runs all IntentOS integration / pilot tests

  Phase 2 — Hyper-V VM (optional, requires admin + Hyper-V):
    - Prints steps to create a Windows Sandbox or Hyper-V quick VM
    - Copies the built binary into a shared folder for in-VM testing

.EXAMPLE
  pwsh -File tools\intentos-vm-validate.ps1
  pwsh -File tools\intentos-vm-validate.ps1 -SkipBuild
  pwsh -File tools\intentos-vm-validate.ps1 -ShowVmGuide
#>
param(
    [switch]$SkipBuild,
    [switch]$ShowVmGuide,
    [switch]$KeepSandbox
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$RustRoot = Join-Path $RepoRoot "rust"
$Sandbox = Join-Path $env:TEMP "intentos-vm-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
$Binary = Join-Path $RustRoot "target\release\intentos.exe"
$Failed = @()
$Passed = 0

function Write-Step([string]$Msg) {
    Write-Host ""
    Write-Host "── $Msg" -ForegroundColor Cyan
}

function Run-Check([string]$Name, [scriptblock]$Block) {
    try {
        & $Block
        $script:Passed++
        Write-Host "[PASS] $Name" -ForegroundColor Green
    } catch {
        $script:Failed += $Name
        Write-Host "[FAIL] $Name — $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host @"

  IntentOS Virtual Environment Validator
  Sandbox: $Sandbox

"@ -ForegroundColor White

# ── Phase 1: isolated sandbox ───────────────────────────────────────────────
Write-Step "Creating isolated state directory"
New-Item -ItemType Directory -Path $Sandbox -Force | Out-Null
$env:INTENTOS_STATE_DIR = $Sandbox
$env:INTENTOS_SKIP_OOBE = "1"
Write-Host "INTENTOS_STATE_DIR=$Sandbox"

if (-not $SkipBuild) {
    Write-Step "Building release binary"
    Push-Location $RustRoot
    try {
        cargo build -p intentos --release 2>&1 | Write-Host
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed (exit $LASTEXITCODE)" }
    } finally {
        Pop-Location
    }
}

if (-not (Test-Path $Binary)) {
    Write-Error "Binary not found: $Binary — run without -SkipBuild"
}

Write-Step "Integration / pilot test suite (run before shell smoke to avoid linker locks)"
Push-Location $RustRoot
try {
    Run-Check "vm_sandbox_pilot" {
        cargo test -p intentos --test vm_sandbox_pilot -- --test-threads=1 2>&1 | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "exit $LASTEXITCODE" }
    }
    Run-Check "ai_os_mvp_pilot" {
        cargo test -p intentos --test ai_os_mvp_pilot 2>&1 | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "exit $LASTEXITCODE" }
    }
    Run-Check "all pilot tests" {
        cargo test -p intentos --tests -- --test-threads=4 2>&1 | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "exit $LASTEXITCODE" }
    }
} finally {
    Pop-Location
}

$ShellCmds = @(
    "1", "2", "3",
    "status", "hal", "posture",
    "kernel stats", "kernel crypto status",
    "audit verify", "broker status",
    "field list", "kb suggest",
    "flow file read",
    "enterprise compat",
    "market status"
)

Write-Step "Shell command smoke tests (isolated profile)"
foreach ($cmd in $ShellCmds) {
    Run-Check "shell: $cmd" {
        & $Binary -c $cmd 2>&1 | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "exit $LASTEXITCODE"
        }
    }
}

Write-Step "OOBE first-run in fresh sandbox"
$OobeSandbox = Join-Path $env:TEMP "intentos-oobe-$(Get-Date -Format 'HHmmss')"
New-Item -ItemType Directory -Path $OobeSandbox -Force | Out-Null
Run-Check "auto-OOBE on first shell open" {
    $prev = $env:INTENTOS_STATE_DIR
    $env:INTENTOS_STATE_DIR = $OobeSandbox
    Remove-Item Env:INTENTOS_SKIP_OOBE -ErrorAction SilentlyContinue
    $out = & $Binary -c "tier" 2>&1
    if ($LASTEXITCODE -ne 0) { throw "exit $LASTEXITCODE" }
    if (-not (Test-Path (Join-Path $OobeSandbox "loom_state.json"))) {
        throw "loom_state.json not created"
    }
    $loom = Get-Content (Join-Path $OobeSandbox "loom_state.json") -Raw
    if ($loom -notmatch "oobe_complete") {
        throw "OOBE did not complete"
    }
    $env:INTENTOS_STATE_DIR = $prev
    $env:INTENTOS_SKIP_OOBE = "1"
    if (-not $KeepSandbox) { Remove-Item -Recurse -Force $OobeSandbox -ErrorAction SilentlyContinue }
}

# ── Phase 2: Hyper-V / Windows Sandbox guide ────────────────────────────────
if ($ShowVmGuide) {
    Write-Step "Hyper-V / Windows Sandbox setup (run as Administrator)"
    Write-Host @"
Option A — Windows Sandbox (fastest, Win10/11 Pro):
  1. Enable:  Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM
  2. Create sandbox script that maps this repo and runs:
       set INTENTOS_STATE_DIR=C:\Users\WDAGUtilityAccount\intentos-test
       C:\mount\rust\target\release\intentos.exe

Option B — Hyper-V Quick Create:
  1. Enable:  Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All
  2. Hyper-V Manager → Quick Create → Windows 11 dev environment
  3. Share folder: $RustRoot\target\release
  4. Inside VM (PowerShell):
       `$env:INTENTOS_STATE_DIR = "`$env:TEMP\intentos-vm"
       .\intentos.exe

Option C — VirtualBox (if Hyper-V unavailable):
  1. Install VirtualBox + Extension Pack
  2. Create VM (2 GB RAM, 20 GB disk), install Windows 10/11
  3. Shared folder → $RepoRoot
  4. Build inside VM: cd rust && cargo build -p intentos --release
  5. Run:  cargo run -p intentos --release

Copy binary to VM shared folder:
  Copy-Item "$Binary" -Destination (Join-Path $RepoRoot "intentos-release.exe")
"@ -ForegroundColor Yellow
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "════════════════════════════════════════" -ForegroundColor White
Write-Host "  Passed: $Passed" -ForegroundColor Green
if ($Failed.Count -gt 0) {
    Write-Host "  Failed: $($Failed.Count)" -ForegroundColor Red
    $Failed | ForEach-Object { Write-Host "    - $_" -ForegroundColor Red }
    Write-Host "════════════════════════════════════════" -ForegroundColor White
    exit 1
}
Write-Host "  All checks passed — IntentOS sandbox healthy" -ForegroundColor Green
Write-Host "════════════════════════════════════════" -ForegroundColor White

if (-not $KeepSandbox) {
    Remove-Item -Recurse -Force $Sandbox -ErrorAction SilentlyContinue
    Write-Host "Sandbox cleaned up. Use -KeepSandbox to inspect state at $Sandbox"
} else {
    Write-Host "Sandbox kept at: $Sandbox"
    Write-Host "  loom:  $(Join-Path $Sandbox 'loom_state.json')"
    Write-Host "  audit: $(Join-Path $Sandbox 'audit.jsonl')"
}

Write-Host ""
Write-Host "For a real VM test, re-run with -ShowVmGuide" -ForegroundColor DarkGray