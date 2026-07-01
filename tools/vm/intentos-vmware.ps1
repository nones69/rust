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
    [ValidateSet("Status", "Setup", "Start", "Stop", "RunTest", "Open", "InstallUbuntu", "PostInstall", "Diagnose", "GuestCommands", "FixHgfs")]
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

function Show-GuestCommands {
    Write-Host @"

══════════════════════════════════════════════════════════════
  Paste this ENTIRE block into the Ubuntu VM (dan@home)
  Works even when vmware-hgfsclient shows nothing
══════════════════════════════════════════════════════════════

sudo apt-get update
sudo apt-get install -y git pkg-config libssl-dev libldap2-dev build-essential rustc cargo
git clone https://github.com/nones69/rust.git ~/rust
cd ~/rust && bash tools/vm/intentos-wsl-test.sh

You should see:
  Cloning into 'rust'...
  Building release...

First build takes 5-15 minutes. If git fails, run: ping -c1 github.com

"@ -ForegroundColor Yellow
}

function Enable-HgfsInVmx([string]$Vmx) {
    $content = Get-Content $Vmx -Raw
    $needed = @(
        'isolation.tools.hgfs.disable = "FALSE"',
        'hgfs.linkRootShare = "TRUE"'
    )
    $lines = Get-Content $Vmx
    foreach ($n in $needed) {
        $key = ($n -split ' = ')[0]
        if (-not ($lines -match "^$([regex]::Escape($key))")) {
            $lines += $n
        }
    }
    $backup = "$Vmx.hgfs.bak"
    Copy-Item $Vmx $backup -Force
    $lines | Set-Content $Vmx -Encoding UTF8
    Write-Host "HGFS VMX flags added. Reboot the VM for shared folders to appear." -ForegroundColor Green
    Write-Host "Backup: $backup"
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
    $list = & $vmrun -T ws list 2>&1 | Out-String
    $leaf = Split-Path $Vmx -Leaf
    return ($list -match [regex]::Escape($leaf) -or $list -match [regex]::Escape($Vmx))
}

function Invoke-GuestProgram([object]$Cfg, [string[]]$GuestArgs) {
    if ([string]::IsNullOrWhiteSpace($Cfg.guest_user)) {
        throw "Guest user required. Pass -GuestUser dan -GuestPassword YOUR_PASS"
    }
    if ([string]::IsNullOrWhiteSpace($Cfg.guest_password)) {
        throw "Guest password required for vmrun automation. Pass -GuestPassword (the password you set during Ubuntu install)."
    }
    $vmArgs = @("-T", "ws", "-gu", $Cfg.guest_user, "-gp", $Cfg.guest_password,
        "runProgramInGuest", $Cfg.vmx_path) + $GuestArgs
    & $vmrun @vmArgs 2>&1
    return $LASTEXITCODE
}

function Set-PostInstallBoot([string]$Vmx) {
    if (Test-VmRunning $Vmx) {
        throw "Power off the VM first: pwsh -File tools\vm\intentos-vmware.ps1 -Action Stop"
    }
    $backup = "$Vmx.postinstall.bak"
    Copy-Item $Vmx $backup -Force
    $lines = Get-Content $Vmx | Where-Object {
        $_ -notmatch '^sata0:1\.' -and $_ -notmatch '^bios\.bootOrder'
    }
    $lines += @(
        'sata0:1.present = "FALSE"',
        'bios.bootOrder = "hdd,cdrom"'
    )
    $lines | Set-Content $Vmx -Encoding UTF8
    Write-Host "Boot order set to disk-first; install ISO disconnected." -ForegroundColor Green
    Write-Host "Backup: $backup"
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
    "Diagnose" {
        Write-Step "Guest diagnostics"
        $tools = & $vmrun -T ws checkToolsState $cfg.vmx_path 2>&1
        Write-Host "VMware Tools: $tools"
        if (Test-VmRunning $cfg.vmx_path) {
            Write-Host "VM state: RUNNING" -ForegroundColor Green
        } else {
            Write-Host "VM state: stopped" -ForegroundColor Yellow
        }
        $ip = & $vmrun -T ws getGuestIPAddress $cfg.vmx_path 2>&1
        Write-Host "Guest IP: $ip"
        if (-not [string]::IsNullOrWhiteSpace($cfg.guest_password)) {
            Write-Host "Trying guest whoami..."
            $code = Invoke-GuestProgram $cfg @("/bin/bash", "-lc", "whoami; vmware-hgfsclient; ls /mnt/hgfs 2>/dev/null || true")
            if ($code -ne 0) {
                Write-Host "Guest login failed — wrong -GuestPassword?" -ForegroundColor Red
            }
        } else {
            Write-Host "No guest_password in config — automated guest commands need -GuestPassword" -ForegroundColor Yellow
        }
        Write-Host ""
        Write-Host "If automated test fails, run inside the VM (copy/paste):" -ForegroundColor Cyan
        Show-GuestCommands
    }
    "GuestCommands" {
        Show-GuestCommands
    }
    "PostInstall" {
        Write-Step "Post-install VM config (boot from disk, eject ISO)"
        Set-PostInstallBoot $cfg.vmx_path
        Write-Host "Start VM: pwsh -File tools\vm\intentos-vmware.ps1 -Action Start -Gui" -ForegroundColor Yellow
    }
    "FixHgfs" {
        Write-Step "Enable VMware shared folders in VMX"
        if (Test-VmRunning $cfg.vmx_path) {
            Write-Host "Reboot the VM after this (or Stop then Start) so hgfs picks up." -ForegroundColor Yellow
        }
        Enable-HgfsInVmx $cfg.vmx_path
        Add-SharedFolder $cfg
    }
    "RunTest" {
        if (-not (Test-VmRunning $cfg.vmx_path)) {
            throw "VM is not running. Start it first: -Action Start -Gui"
        }
        if ([string]::IsNullOrWhiteSpace($cfg.guest_user) -or [string]::IsNullOrWhiteSpace($cfg.guest_password)) {
            Write-Host @"
Guest credentials required for automated test.

  pwsh -File tools\vm\intentos-vmware.ps1 -Action RunTest -GuestUser dan -GuestPassword YOUR_UBUNTU_PASSWORD

Manual (inside VM — use -Action GuestCommands for full copy/paste block):
  bash /mnt/hgfs/IntentOS/tools/vm/intentos-vmware-guest.sh
"@ -ForegroundColor Yellow
            exit 1
        }
        Write-Step "Running IntentOS test in VMware guest (via runProgramInGuest)"
        $guestScript = "/mnt/hgfs/IntentOS/tools/vm/intentos-vmware-guest.sh"
        $code = Invoke-GuestProgram $cfg @("/bin/bash", $guestScript)
        if ($code -ne 0) {
            Write-Host @"

Guest test failed (exit $code).

Common causes:
  • Wrong -GuestPassword (must match Ubuntu install password)
  • Shared folder not mounted — run -Action GuestCommands inside the VM
  • Missing build deps — guest script installs them on first run

Run: pwsh -File tools\vm\intentos-vmware.ps1 -Action Diagnose -GuestUser $($cfg.guest_user) -GuestPassword ***
"@ -ForegroundColor Red
            exit $code
        }
        Write-Host "VMware guest test passed." -ForegroundColor Green
    }
}