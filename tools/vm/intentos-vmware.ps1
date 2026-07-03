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
    [ValidateSet("Status", "Setup", "Start", "Stop", "RunTest", "Open", "InstallUbuntu", "PostInstall", "Diagnose", "GuestCommands", "FixHgfs", "FixNetwork", "Fix", "SnapshotList", "SnapshotCreate", "SnapshotRevert", "SnapshotDelete", "CaptureScreen", "IsoStatus", "IsoGuestCommands", "AttachIso", "BootIso", "GuestIsoBuild")]
    [string]$Action = "Status",
    [string]$VmxPath,
    [string]$GuestUser,
    [string]$GuestPassword,
    [string]$SnapshotName = "Snapshot 1",
    [string]$IsoPath,
    [ValidateSet("network", "deps", "rust-os", "ubuntu-live", "iso", "all")]
    [string]$IsoBuildStage = "all",
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

function Get-CustomIsoPath {
    if ($IsoPath) { return $IsoPath }
    return Join-Path $RepoRoot "iso-build\dist\custom-os.iso"
}

function Show-IsoGuestCommands {
    Write-Host @"

══════════════════════════════════════════════════════════════
  iso-build — VMware guest (paste as dan@home)
══════════════════════════════════════════════════════════════

# Step 1: network + clone
sudo ip link set ens33 up 2>/dev/null || sudo ip link set eth0 up 2>/dev/null || true
sudo dhclient -v ens33 2>/dev/null || sudo dhclient -v eth0 2>/dev/null || sudo dhclient -v
printf 'nameserver 8.8.8.8\nnameserver 1.1.1.1\n' | sudo tee /etc/resolv.conf
ping -c2 github.com

git clone https://github.com/nones69/rust.git ~/rust 2>/dev/null || (cd ~/rust && git pull)
bash ~/rust/tools/vm/intentos-vmware-iso-guest.sh rust-os    # quick kernel test (~5 min)
# Full ISO (20–90 min):
# bash ~/rust/tools/vm/intentos-vmware-iso-guest.sh all

══════════════════════════════════════════════════════════════
  After ISO exists on Windows host — boot in VMware:
══════════════════════════════════════════════════════════════

  pwsh -File tools\vm\intentos-vmware.ps1 -Action BootIso
  # Select "Custom OS — Live Session" or "Rust OS Kernel" in GRUB

"@ -ForegroundColor Yellow
}

function Set-IsoBoot([string]$Vmx, [string]$Iso) {
    if (-not (Test-Path $Iso)) {
        throw "ISO not found: $Iso — build on guest first (-Action IsoGuestCommands) or WSL: cd iso-build && make all"
    }
    if (Test-VmRunning $Vmx) {
        throw "Power off VM first: -Action Stop"
    }
    $isoEsc = $Iso -replace '\\', '\\'
    $lines = Get-Content $Vmx | Where-Object {
        $_ -notmatch '^sata0:1\.' -and $_ -notmatch '^bios\.bootOrder'
    }
    $lines += @(
        'sata0:1.present = "TRUE"',
        'sata0:1.deviceType = "cdrom-image"',
        "sata0:1.fileName = `"$isoEsc`"",
        'bios.bootOrder = "cdrom,hdd"'
    )
    $backup = "$Vmx.isoboot.bak"
    Copy-Item $Vmx $backup -Force
    $lines | Set-Content $Vmx -Encoding UTF8
    Write-Host "Attached ISO: $Iso" -ForegroundColor Green
    Write-Host "Boot order: cdrom,hdd (backup: $backup)" -ForegroundColor Green
}

function Invoke-GuestIsoBuild([object]$Cfg, [string]$Stage) {
    $cmd = "bash `"`$HOME/rust/tools/vm/intentos-vmware-iso-guest.sh`" $Stage"
    return Invoke-GuestProgram $Cfg @("/bin/bash", "-lc", $cmd)
}

function Show-GuestCommands {
    Write-Host @"

══════════════════════════════════════════════════════════════
  Step 1 — fix network (paste in Ubuntu VM as dan@home)
══════════════════════════════════════════════════════════════

sudo ip link set ens33 up 2>/dev/null || sudo ip link set eth0 up 2>/dev/null || true
sudo dhclient -v ens33 2>/dev/null || sudo dhclient -v eth0 2>/dev/null || sudo dhclient -v
printf 'nameserver 8.8.8.8\nnameserver 1.1.1.1\n' | sudo tee /etc/resolv.conf
ping -c2 8.8.8.8
ping -c2 github.com

══════════════════════════════════════════════════════════════
  Step 2 — IntentOS test (after ping works)
══════════════════════════════════════════════════════════════

sudo apt-get update
sudo apt-get install -y git pkg-config libssl-dev libldap2-dev build-essential rustc cargo
git clone https://github.com/nones69/rust.git ~/rust
cd ~/rust && bash tools/vm/intentos-wsl-test.sh

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

function Repair-HostVmwareNetworking {
    $fixHost = Join-Path $VmTools "intentos-vmware-fix-host.ps1"
    if (-not (Test-Path $fixHost)) {
        Write-Host "Host fix script missing: $fixHost" -ForegroundColor Yellow
        return
    }
    Write-Host "Starting VMware NAT/DHCP (UAC prompt may appear)..." -ForegroundColor Yellow
    Start-Process pwsh -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$fixHost`"" -Wait
    Get-Service VMnetDHCP, "VMware NAT Service" -ErrorAction SilentlyContinue |
        Format-Table Name, Status -AutoSize
}

function Set-BridgedNetwork([string]$Vmx) {
    $backup = "$Vmx.bridged.bak"
    Copy-Item $Vmx $backup -Force
    $seenBridge = $false
    $lines = foreach ($line in Get-Content $Vmx) {
        if ($line -match '^ethernet0\.connectionType') {
            'ethernet0.connectionType = "bridged"'
        } elseif ($line -match '^ethernet0\.(vnet|bridgeName)') {
            $seenBridge = $true
            'ethernet0.bridgeName = "Automatic"'
        } else {
            $line
        }
    }
    if (-not $seenBridge) {
        $lines += 'ethernet0.bridgeName = "Automatic"'
    }
    $lines | Set-Content $Vmx -Encoding UTF8
    Write-Host "Network set to bridged (home router DHCP)." -ForegroundColor Green
    Write-Host "Backup: $backup"
}

function Set-GuestOs64([string]$Vmx) {
    $backup = "$Vmx.guestos.bak"
    Copy-Item $Vmx $backup -Force
    $lines = foreach ($line in Get-Content $Vmx) {
        if ($line -match '^guestOS\s*=') {
            'guestOS = "ubuntu-64"'
        } else {
            $line
        }
    }
    $lines | Set-Content $Vmx -Encoding UTF8
    Write-Host 'guestOS set to ubuntu-64 (64-bit VMware profile).' -ForegroundColor Green
}

function Set-NatNetwork([string]$Vmx) {
    $backup = "$Vmx.nat.bak"
    Copy-Item $Vmx $backup -Force
    $lines = Get-Content $Vmx | Where-Object {
        $_ -notmatch '^ethernet0\.bridgeName' -and $_ -notmatch '^ethernet0\.vnet'
    }
    $lines = foreach ($line in $lines) {
        if ($line -match '^ethernet0\.connectionType') {
            'ethernet0.connectionType = "nat"'
        } else {
            $line
        }
    }
    $lines | Set-Content $Vmx -Encoding UTF8
    Write-Host "Network set to NAT (VMware VMnet8 — recommended)." -ForegroundColor Green
    Write-Host "Backup: $backup"
}

function Invoke-GuestGitTest([object]$Cfg) {
    $cmd = @'
set -e
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq
sudo apt-get install -y git pkg-config libssl-dev libldap2-dev build-essential rustc cargo
[ -d "$HOME/rust/.git" ] || git clone --depth 1 https://github.com/nones69/rust.git "$HOME/rust"
cd "$HOME/rust" && bash tools/vm/intentos-wsl-test.sh
'@
    return Invoke-GuestProgram $Cfg @("/bin/bash", "-lc", $cmd)
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
    "IsoStatus" {
        Write-Step "iso-build artifact status"
        $iso = Get-CustomIsoPath
        $elf = Join-Path $RepoRoot "iso-build\build\rust-os\rust-os.elf"
        if (Test-Path $iso) {
            $sz = (Get-Item $iso).Length / 1GB
            Write-Host "ISO: $iso ($([math]::Round($sz, 2)) GiB)" -ForegroundColor Green
        } else {
            Write-Host "ISO: not built yet ($iso)" -ForegroundColor Yellow
        }
        if (Test-Path $elf) {
            Write-Host "Kernel ELF: $elf" -ForegroundColor Green
        } else {
            Write-Host "Kernel ELF: not built ($elf)" -ForegroundColor DarkGray
        }
        Write-Host ""
        Write-Host "Guest build: -Action IsoGuestCommands" -ForegroundColor Cyan
        Write-Host "Boot ISO:    -Action BootIso (after ISO exists)" -ForegroundColor Cyan
    }
    "IsoGuestCommands" {
        Show-IsoGuestCommands
    }
    "AttachIso" {
        Write-Step "Attach custom-os.iso to VM CD-ROM"
        $iso = Get-CustomIsoPath
        Set-IsoBoot $cfg.vmx_path $iso
        Write-Host "Start VM: -Action Start -Gui" -ForegroundColor Yellow
    }
    "BootIso" {
        Write-Step "Boot VMware VM from custom-os.iso"
        Repair-HostVmwareNetworking
        $iso = Get-CustomIsoPath
        Set-IsoBoot $cfg.vmx_path $iso
        & $vmrun -T ws start $cfg.vmx_path gui
        Write-Host @"

VM booting from custom-os.iso. In GRUB menu choose:
  • Custom OS — Live Session (Ubuntu 24.04 Noble)  [default]
  • Rust OS Kernel — Bare Metal (x86_64 no_std)

After testing, restore disk boot: -Action PostInstall

"@ -ForegroundColor Green
    }
    "GuestIsoBuild" {
        if (-not (Test-VmRunning $cfg.vmx_path)) {
            throw "VM not running. Start first: -Action Start -Gui"
        }
        if ([string]::IsNullOrWhiteSpace($cfg.guest_password)) {
            Write-Host "Automated guest build needs -GuestPassword. Or paste -Action IsoGuestCommands" -ForegroundColor Yellow
            Show-IsoGuestCommands
            exit 1
        }
        Write-Step "Building iso-build stage '$IsoBuildStage' in guest"
        $code = Invoke-GuestIsoBuild $cfg $IsoBuildStage
        if ($code -ne 0) {
            Write-Host "Guest iso-build failed (exit $code). Try manual: -Action IsoGuestCommands" -ForegroundColor Red
            exit $code
        }
        Write-Host "Guest iso-build stage '$IsoBuildStage' finished." -ForegroundColor Green
        if ($IsoBuildStage -eq "all" -or $IsoBuildStage -eq "iso") {
            $iso = Get-CustomIsoPath
            if (Test-Path $iso) {
                Write-Host "ISO ready. Boot: -Action BootIso" -ForegroundColor Green
            }
        }
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
    "FixNetwork" {
        & $PSCommandPath -Action Fix
    }
    "Fix" {
        Write-Step "Fix VMware guest network + boot config"
        Repair-HostVmwareNetworking
        if (Test-VmRunning $cfg.vmx_path) {
            Write-Host "Stopping VM to apply network changes..."
            & $vmrun -T ws stop $cfg.vmx_path soft
            Start-Sleep -Seconds 5
        }
        Set-GuestOs64 $cfg.vmx_path
        Set-NatNetwork $cfg.vmx_path
        Set-PostInstallBoot $cfg.vmx_path
        Enable-HgfsInVmx $cfg.vmx_path
        Write-Step "Starting VM"
        & $vmrun -T ws start $cfg.vmx_path gui
        Write-Host @"

VM rebooted with NAT networking (VMnet8). VMware NAT/DHCP must stay running on Windows.

In the VM terminal (dan@home), run Step 1 then Step 2 below:

"@ -ForegroundColor Green
        Show-GuestCommands
    }
    "CaptureScreen" {
        Write-Step "Capture VM screen to PNG"
        $out = Join-Path $VmTools "vm-screen.png"
        if ($SnapshotName) {
            $out = Join-Path $VmTools "vm-screen-$($SnapshotName -replace ' ','-').png"
        }
        $capArgs = @("-T", "ws")
        if (-not [string]::IsNullOrWhiteSpace($cfg.guest_user) -and -not [string]::IsNullOrWhiteSpace($cfg.guest_password)) {
            $capArgs += @("-gu", $cfg.guest_user, "-gp", $cfg.guest_password)
        }
        $capArgs += @("captureScreen", $cfg.vmx_path, $out)
        if ($SnapshotName) {
            $capArgs += "-snapshot=$SnapshotName"
        }
        & $vmrun @capArgs 2>&1
        if (-not (Test-Path $out)) {
            Write-Host @"
Screen capture needs guest login on this VM. Re-run with password:

  pwsh -File tools\vm\intentos-vmware.ps1 -Action CaptureScreen -GuestUser dan -GuestPassword YOUR_PASS -SnapshotName "Snapshot 1"

Or paste/drag a screenshot of the VMware window into chat.
"@ -ForegroundColor Yellow
            exit 1
        }
        Write-Host "Saved: $out" -ForegroundColor Green
    }
    "SnapshotList" {
        Write-Step "VM snapshots"
        & $vmrun -T ws listSnapshots $cfg.vmx_path
    }
    "SnapshotCreate" {
        Write-Step "Creating snapshot: $SnapshotName"
        if (-not (Test-VmRunning $cfg.vmx_path)) {
            & $vmrun -T ws start $cfg.vmx_path nogui
            Start-Sleep -Seconds 3
        }
        & $vmrun -T ws snapshot $cfg.vmx_path $SnapshotName
        Write-Host "Created: $SnapshotName" -ForegroundColor Green
    }
    "SnapshotRevert" {
        Write-Step "Reverting to snapshot: $SnapshotName"
        if (Test-VmRunning $cfg.vmx_path) {
            & $vmrun -T ws stop $cfg.vmx_path soft
            Start-Sleep -Seconds 5
        }
        & $vmrun -T ws revertToSnapshot $cfg.vmx_path $SnapshotName
        Write-Host "Reverted to: $SnapshotName" -ForegroundColor Green
        Write-Host "Start VM: -Action Start -Gui" -ForegroundColor Yellow
        Write-Host "Then run network fix in guest (GuestCommands Step 1) or: -Action Fix" -ForegroundColor Yellow
    }
    "SnapshotDelete" {
        Write-Step "Deleting snapshot: $SnapshotName"
        & $vmrun -T ws deleteSnapshot $cfg.vmx_path $SnapshotName
        Write-Host "Deleted: $SnapshotName" -ForegroundColor Green
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
        Write-Step "Running IntentOS test in VMware guest (git clone path)"
        $code = Invoke-GuestGitTest $cfg
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