#Requires -Version 5.1
<#
.SYNOPSIS
  IntentOS testing in VMware Workstation (Ubuntu or Windows guest).

.EXAMPLE
  pwsh -File tools\vm\intentos-vmware.ps1 -Action Status
  pwsh -File tools\vm\intentos-vmware.ps1 -Action Setup
  pwsh -File tools\vm\intentos-vmware.ps1 -Action Start
  pwsh -File tools\vm\intentos-vmware.ps1 -Action RunTest -GuestUser dan
#>
param(
    [ValidateSet("Status", "Setup", "Start", "Stop", "RunTest", "Open", "InstallUbuntu")]
    [string]$Action = "Status",
    [string]$VmxPath,
    [string]$GuestUser,
    [string]$GuestPassword,
    [switch]$Gui,
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$VmTools = $PSScriptRoot
$RepoRoot = Split-Path -Parent (Split-Path -Parent $VmTools)
$RustRoot = Join-Path $RepoRoot "rust"
$ConfigPath = Join-Path $VmTools "intentos-vmware.config.json"
$BundleDir = Join-Path $RepoRoot "vm-bundle"

function Write-Step([string]$Msg) {
    Write-Host ""
    Write-Host "── $Msg" -ForegroundColor Cyan
}

function Find-VmRun {
    $candidates = @(
        "${env:ProgramFiles(x86)}\VMware\VMware Workstation\vmrun.exe",
        "$env:ProgramFiles\VMware\VMware Workstation\vmrun.exe"
    )
    foreach ($p in $candidates) {
        if (Test-Path $p) { return $p }
    }
    return $null
}

function Get-VmConfig {
    if (-not (Test-Path $ConfigPath)) {
        throw "Config missing: $ConfigPath"
    }
    $cfg = Get-Content $ConfigPath -Raw | ConvertFrom-Json
    if ($VmxPath) { $cfg.vmx_path = $VmxPath }
    if ($GuestUser) { $cfg.guest_user = $GuestUser }
    if ($GuestPassword) { $cfg.guest_password = $GuestPassword }
    if (-not (Test-Path $cfg.vmx_path)) {
        throw "VMX not found: $($cfg.vmx_path) — edit intentos-vmware.config.json"
    }
    return $cfg
}

function Test-VmRunning([string]$Vmx) {
    $vmrun = Find-VmRun
    $list = & $vmrun -T ws list 2>&1
    $norm = $Vmx -replace '\\', '/'
    return ($list -match [regex]::Escape($norm) -or $list -match [regex]::Escape($Vmx))
}

function Add-SharedFolder([object]$Cfg) {
    $vmx = $Cfg.vmx_path
    $content = Get-Content $vmx -Raw
    if ($content -match 'sharedFolder0\.hostPath') {
        Write-Host "Shared folder already configured in VMX." -ForegroundColor Yellow
        return
    }
    if (Test-VmRunning $vmx) {
        throw "Power off the VM before adding a shared folder (VMware → Power → Shut Down Guest)"
    }
    $backup = "$vmx.intentos.bak"
    Copy-Item $vmx $backup -Force
    $hostPath = $Cfg.shared_folder_host -replace '\\', '\\'
    $block = @"

sharedFolder.maxNum = "1"
sharedFolder0.present = "TRUE"
sharedFolder0.enabled = "TRUE"
sharedFolder0.hostPath = "$($Cfg.shared_folder_host)"
sharedFolder0.guestName = "$($Cfg.shared_folder_guest)"
sharedFolder0.expires = "FALSE"
sharedFolder0.readOnly = "FALSE"
"@
    Add-Content -Path $vmx -Value $block -Encoding UTF8
    Write-Host "Added shared folder '$($Cfg.shared_folder_guest)' → $($Cfg.shared_folder_host)" -ForegroundColor Green
    Write-Host "Backup: $backup"
}

function Build-Release {
    if ($SkipBuild -and (Test-Path (Join-Path $RustRoot "target\release\intentos.exe"))) { return }
    Write-Step "Building Windows release (for vm-bundle)"
    Push-Location $RustRoot
    try {
        cargo build -p intentos --release
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
    } finally {
        Pop-Location
    }
}

function New-Bundle {
    $bin = Join-Path $RustRoot "target\release\intentos.exe"
    if (-not (Test-Path $bin)) { Build-Release }
    New-Item -ItemType Directory -Force -Path $BundleDir | Out-Null
    Copy-Item $bin (Join-Path $BundleDir "intentos.exe") -Force
    Copy-Item (Join-Path $VmTools "intentos-guest-test.ps1") $BundleDir -Force
    Copy-Item (Join-Path $VmTools "intentos-vmware-guest.sh") $BundleDir -Force
}

$vmrun = Find-VmRun
if (-not $vmrun) {
    Write-Error @"
VMware vmrun.exe not found. Install VMware Workstation:
  winget install VMware.Workstation
"@
}

$cfg = Get-VmConfig

Write-Host @"

  IntentOS — VMware Workstation
  VM:     $($cfg.vmx_path)
  Share:  $($cfg.shared_folder_guest) → $($cfg.shared_folder_host)

"@ -ForegroundColor White

switch ($Action) {
    "Status" {
        Write-Step "VMware status"
        Write-Host "vmrun: $vmrun"
        & $vmrun -T ws list
        if (Test-VmRunning $cfg.vmx_path) {
            Write-Host "IntentOS VM: RUNNING" -ForegroundColor Green
        } else {
            Write-Host "IntentOS VM: stopped" -ForegroundColor DarkGray
        }
    }
    "Setup" {
        Write-Step "VMware + IntentOS setup"
        Build-Release
        New-Bundle
        Add-SharedFolder $cfg
        Write-Host @"

Next steps:
  1. Start VM:     pwsh -File tools\vm\intentos-vmware.ps1 -Action Start -Gui
  2. In Ubuntu guest (first time only):
       sudo apt-get install -y open-vm-tools open-vm-tools-desktop
       sudo apt-get install -y pkg-config libssl-dev libldap2-dev build-essential
       # verify share:  vmware-hgfsclient
       # mount if needed: sudo mount -t fuse.vmhgfs-fuse .host:/IntentOS /mnt/hgfs/IntentOS
  3. Run test:     pwsh -File tools\vm\intentos-vmware.ps1 -Action RunTest -GuestUser YOUR_USER

Windows guest alternative:
  Copy $BundleDir into the VM and run .\intentos-guest-test.ps1
"@ -ForegroundColor Yellow
    }
    "Start" {
        Write-Step "Starting VM"
        $mode = if ($Gui) { "gui" } else { "nogui" }
        & $vmrun -T ws start $cfg.vmx_path $mode
        Write-Host "VM started ($mode). Wait for guest OS to boot, then RunTest."
    }
    "Stop" {
        Write-Step "Stopping VM"
        & $vmrun -T ws stop $cfg.vmx_path soft
    }
    "Open" {
        $ws = Join-Path (Split-Path $vmrun) "vmware.exe"
        if (Test-Path $ws) {
            Start-Process $ws
        } else {
            Start-Process $vmrun -ArgumentList @("-T", "ws", "start", $cfg.vmx_path, "gui")
        }
    }
    "InstallUbuntu" {
        $install = Join-Path $VmTools "intentos-vmware-install-ubuntu.ps1"
        & $install -StartVm
    }
    "RunTest" {
        if (-not (Test-VmRunning $cfg.vmx_path)) {
            throw "VM is not running. Start it first: -Action Start -Gui"
        }
        if ([string]::IsNullOrWhiteSpace($cfg.guest_user)) {
            Write-Host @"
Guest credentials required for automated test.

Option A — automated (Linux guest):
  pwsh -File tools\vm\intentos-vmware.ps1 -Action RunTest -GuestUser YOUR_USER -GuestPassword YOUR_PASS

Option B — manual (inside Ubuntu VM terminal):
  bash /mnt/hgfs/IntentOS/tools/vm/intentos-vmware-guest.sh

Option C — Windows guest:
  cd C:\IntentOS
  .\intentos-guest-test.ps1
"@ -ForegroundColor Yellow
            exit 1
        }
        Write-Step "Running IntentOS test in VMware guest"
        $guestScript = "/bin/bash /mnt/hgfs/IntentOS/tools/vm/intentos-vmware-guest.sh"
        $args = @("-T", "ws", "-gu", $cfg.guest_user, "-gp", $cfg.guest_password,
            "runScriptInGuest", $cfg.vmx_path, $guestScript)
        & $vmrun @args
        if ($LASTEXITCODE -ne 0) {
            throw "Guest test failed (exit $LASTEXITCODE). Ensure open-vm-tools + shared folder are active."
        }
        Write-Host "VMware guest test passed." -ForegroundColor Green
    }
}