#Requires -Version 5.1
<#
.SYNOPSIS
  Download Ubuntu Server ISO and attach it to the IntentOS VMware VM for first-time install.

.EXAMPLE
  pwsh -File tools\vm\intentos-vmware-install-ubuntu.ps1
  pwsh -File tools\vm\intentos-vmware-install-ubuntu.ps1 -IsoPath C:\Downloads\ubuntu.iso
#>
param(
    [string]$IsoPath,
    [switch]$SkipDownload,
    [switch]$StartVm
)

$ErrorActionPreference = "Stop"
$VmTools = $PSScriptRoot
$ConfigPath = Join-Path $VmTools "intentos-vmware.config.json"
$IsoDir = Join-Path $env:USERPROFILE "Downloads\IntentOS-VM"
$DefaultIso = Join-Path $IsoDir "ubuntu-24.04.4-live-server-amd64.iso"
$IsoUrl = "https://releases.ubuntu.com/24.04/ubuntu-24.04.4-live-server-amd64.iso"

function Write-Step([string]$Msg) {
    Write-Host ""
    Write-Host "── $Msg" -ForegroundColor Cyan
}

function Find-VmRun {
    "${env:ProgramFiles(x86)}\VMware\VMware Workstation\vmrun.exe"
}

$cfg = Get-Content $ConfigPath -Raw | ConvertFrom-Json
$vmx = $cfg.vmx_path
$vmrun = Find-VmRun

if (-not $IsoPath) { $IsoPath = $DefaultIso }
New-Item -ItemType Directory -Force -Path $IsoDir | Out-Null

Write-Step "Stopping VM (if running)"
& $vmrun -T ws stop $vmx soft 2>$null
if ($LASTEXITCODE -ne 0) {
    & $vmrun -T ws stop $vmx hard 2>$null
}

if (-not $SkipDownload -and -not (Test-Path $IsoPath)) {
    Write-Step "Downloading Ubuntu Server 24.04 ISO (~2.6 GB)"
    Write-Host "URL: $IsoUrl"
    Write-Host "This may take several minutes..."
    Invoke-WebRequest -Uri $IsoUrl -OutFile $IsoPath -UseBasicParsing
    Write-Host "Downloaded: $IsoPath" -ForegroundColor Green
} elseif (Test-Path $IsoPath) {
    Write-Host "Using ISO: $IsoPath" -ForegroundColor Green
} else {
    Write-Error "ISO not found at $IsoPath — download Ubuntu Server ISO manually or omit -SkipDownload"
}

Write-Step "Attaching ISO and setting boot order"
$vmxContent = Get-Content $vmx -Raw
$isoEsc = $IsoPath -replace '\\', '\\'

# Remove old cdrom lines and re-add
$lines = Get-Content $vmx | Where-Object {
    $_ -notmatch '^sata0:1\.' -and $_ -notmatch '^bios\.bootOrder'
}
$lines += @(
    'sata0:1.present = "TRUE"',
    'sata0:1.deviceType = "cdrom-image"',
    "sata0:1.fileName = `"$isoEsc`"",
    'bios.bootOrder = "cdrom,hdd"'
)
$backup = "$vmx.preinstall.bak"
Copy-Item $vmx $backup -Force
$lines | Set-Content $vmx -Encoding UTF8
Write-Host "VMX updated (backup: $backup)" -ForegroundColor Green

Write-Host @"

══════════════════════════════════════════════════════════════
  Ubuntu install — follow these steps in the VMware window
══════════════════════════════════════════════════════════════

  1. VM boots from ISO → Ubuntu Server installer starts
  2. Language: English
  3. Keyboard: your layout
  4. Install Ubuntu Server (use defaults)
  5. Network: enable DHCP (NAT — already configured)
  6. Storage: Use entire disk (Ubuntu (2).vmdk — ~20GB)
  7. Profile:
       Your name:     intentos
       Server name:   intentos-vm
       Username:      intentos
       Password:      (pick one you'll remember)
  8. SSH: ✓ Install OpenSSH server
  9. Snaps: skip all (Tab to Done)
  10. Wait for install → Reboot Now
  11. When prompted, press ENTER to remove installation medium
      (or VM → Removable Devices → CD/DVD → Disconnect)

After reboot, log in as 'intentos' and run:

  sudo apt-get update
  sudo apt-get install -y open-vm-tools open-vm-tools-desktop
  sudo apt-get install -y pkg-config libssl-dev libldap2-dev build-essential rustc cargo
  vmware-hgfsclient
  bash /mnt/hgfs/IntentOS/tools/vm/intentos-vmware-guest.sh

Then from Windows (optional automated test):
  pwsh -File tools\vm\intentos-vmware.ps1 -Action RunTest -GuestUser intentos -GuestPassword YOUR_PASS

"@ -ForegroundColor Yellow

if ($StartVm) {
    Write-Step "Starting VM with installer"
    & $vmrun -T ws start $vmx gui
    Write-Host "VM started — complete the installer in the VMware window." -ForegroundColor Green
}