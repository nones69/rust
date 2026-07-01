#Requires -Version 5.1
<#
.SYNOPSIS
  Set up IntentOS testing in a virtual environment (WSL2, Windows Sandbox, or VirtualBox).

.EXAMPLE
  pwsh -File tools\vm\intentos-vm-setup.ps1
  pwsh -File tools\vm\intentos-vm-setup.ps1 -Target WSL
  pwsh -File tools\vm\intentos-vm-setup.ps1 -Target Sandbox
  pwsh -File tools\vm\intentos-vm-setup.ps1 -Target VirtualBox
  pwsh -File tools\vm\intentos-vm-setup.ps1 -Target VMware
#>
param(
    [ValidateSet("Auto", "WSL", "Sandbox", "VirtualBox", "VMware", "Bundle")]
    [string]$Target = "Auto",
    [switch]$RunTest,
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$RustRoot = Join-Path $RepoRoot "rust"
$BundleDir = Join-Path $RepoRoot "vm-bundle"
$Binary = Join-Path $RustRoot "target\release\intentos.exe"
$VmTools = $PSScriptRoot

function Write-Step([string]$Msg) {
    Write-Host ""
    Write-Host "── $Msg" -ForegroundColor Cyan
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-Wsl {
    try {
        wsl --status *> $null
        return $true
    } catch { return $false }
}

function Test-SandboxFeature {
    if (-not (Test-Admin)) { return $false }
    $f = Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -ErrorAction SilentlyContinue
    return ($f.State -eq "Enabled")
}

function Test-VirtualBox {
    return [bool](Get-Command VBoxManage -ErrorAction SilentlyContinue)
}

function Test-VMware {
    $paths = @(
        "${env:ProgramFiles(x86)}\VMware\VMware Workstation\vmrun.exe",
        "$env:ProgramFiles\VMware\VMware Workstation\vmrun.exe"
    )
    return ($paths | Where-Object { Test-Path $_ } | Select-Object -First 1)
}

function Build-HostBinary {
    if ($SkipBuild -and (Test-Path $Binary)) { return }
    Write-Step "Building Windows release binary"
    Push-Location $RustRoot
    try {
        cargo build -p intentos --release
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
    } finally {
        Pop-Location
    }
}

function New-VmBundle {
    Write-Step "Creating VM bundle at $BundleDir"
    New-Item -ItemType Directory -Force -Path $BundleDir | Out-Null
    Copy-Item $Binary -Destination (Join-Path $BundleDir "intentos.exe") -Force
    Copy-Item (Join-Path $VmTools "intentos-guest-test.ps1") -Destination $BundleDir -Force
    Copy-Item (Join-Path $RepoRoot "tools\intentos-vm-validate.ps1") -Destination $BundleDir -Force
    Copy-Item (Join-Path $VmTools "intentos-wsl-test.sh") -Destination $BundleDir -Force
    @"
IntentOS VM bundle
==================
Windows guest (copy vm-bundle folder into VM):
  .\intentos-guest-test.ps1

Full validator (host or guest with repo):
  pwsh -File intentos-vm-validate.ps1

WSL2 Linux VM:
  bash intentos-wsl-test.sh
"@ | Set-Content (Join-Path $BundleDir "README.txt") -Encoding UTF8
    Write-Host "Bundle ready: $BundleDir" -ForegroundColor Green
}

function Invoke-WslTest {
    Write-Step "WSL2 Linux VM test"
    $script = Join-Path $VmTools "intentos-wsl-test.sh"
    wsl -d Ubuntu -- bash -lc "sed -i 's/\r$//' '$($script -replace '\\','/')' 2>/dev/null; bash '$($script -replace '\\','/')'"
    if ($LASTEXITCODE -ne 0) { throw "WSL test failed (exit $LASTEXITCODE)" }
}

function Write-SandboxConfig {
    $wsb = Join-Path $VmTools "intentos-sandbox.wsb"
    $hostPath = $RepoRoot -replace '\\', '\\'
    @"
<Configuration>
  <VGpu>Enable</VGpu>
  <Networking>Enable</Networking>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>$RepoRoot</HostFolder>
      <SandboxFolder>C:\IntentOS</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\IntentOS\tools\vm\intentos-guest-test.ps1 -Binary C:\IntentOS\rust\target\release\intentos.exe</Command>
  </LogonCommand>
</Configuration>
"@ | Set-Content $wsb -Encoding UTF8
}

function Invoke-Sandbox {
    Write-Step "Windows Sandbox (requires Windows Pro/Enterprise)"
    Write-SandboxConfig
    $wsb = Join-Path $VmTools "intentos-sandbox.wsb"
    if (-not (Test-SandboxFeature)) {
        Write-Host @"
Windows Sandbox is not enabled. Run PowerShell AS ADMINISTRATOR:

  Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM

Note: Windows Sandbox requires Windows 11 Pro/Enterprise (not Home).
On Windows 11 Home, use WSL2 instead:  -Target WSL
"@ -ForegroundColor Yellow
        if ($Target -eq "Sandbox") { exit 1 }
        return
    }
    Build-HostBinary
    Write-Host "Launching Windows Sandbox — auto-runs guest test on login." -ForegroundColor Green
    Write-Host "Edit MappedFolder HostFolder in intentos-sandbox.wsb if your repo path differs."
    Start-Process $wsb
}

function Invoke-VirtualBoxSetup {
    Write-Step "VirtualBox VM setup"
    if (-not (Test-VirtualBox)) {
        Write-Host @"
VirtualBox not found. Install with:

  winget install Oracle.VirtualBox

Then re-run:  pwsh -File tools\vm\intentos-vm-setup.ps1 -Target VirtualBox

Manual steps after install:
  1. Create VM: IntentOS-Test (Win10/11, 4GB RAM, 40GB disk)
  2. Install Windows in the VM
  3. Shared folder: host $BundleDir  ->  guest C:\IntentOS
  4. In guest PowerShell:
       cd C:\IntentOS
       .\intentos-guest-test.ps1
"@ -ForegroundColor Yellow
        if ($Target -eq "VirtualBox") { exit 1 }
        return
    }
    $vmName = "IntentOS-Test"
    $vms = & VBoxManage list vms 2>$null
    if ($vms -match "`"$vmName`"") {
        Write-Host "VM '$vmName' already exists — start it in VirtualBox Manager." -ForegroundColor Yellow
    } else {
        Write-Host @"
Create the VM in VirtualBox Manager (GUI recommended on first setup):
  Name:     $vmName
  ISO:      Windows 11 installer
  RAM:      4096 MB
  Disk:     40 GB VDI dynamic
  Shared:   $BundleDir  (auto-mount)

Or use Hyper-V / VMware if you have Pro — copy vm-bundle into the guest.
"@ -ForegroundColor Yellow
    }
}

# ── Main ──────────────────────────────────────────────────────────────────────
Write-Host @"

  IntentOS Virtual Machine Setup
  Repo: $RepoRoot
  OS:   Windows 11 Home — WSL2 recommended

"@ -ForegroundColor White

Build-HostBinary
New-VmBundle

if ($Target -eq "Auto") {
    if (Test-VMware) { $Target = "VMware" }
    elseif (Test-Wsl) { $Target = "WSL" }
    elseif (Test-SandboxFeature) { $Target = "Sandbox" }
    elseif (Test-VirtualBox) { $Target = "VirtualBox" }
    else { $Target = "Bundle" }
    Write-Host "Auto-selected target: $Target" -ForegroundColor DarkGray
}

switch ($Target) {
    "WSL" {
        if (-not (Test-Wsl)) {
            Write-Error "WSL not available. Run: wsl --install"
        }
        if ($RunTest -or $Target -ne "Bundle") { Invoke-WslTest }
    }
    "Sandbox" { Invoke-Sandbox }
    "VirtualBox" { Invoke-VirtualBoxSetup }
    "VMware" {
        Write-Step "VMware Workstation"
        & (Join-Path $VmTools "intentos-vmware.ps1") -Action Setup -SkipBuild:$(if ($SkipBuild) { $true } else { $false })
    }
    "Bundle" {
        Write-Step "Bundle-only mode"
        Write-Host "Copy $BundleDir into any Windows VM and run intentos-guest-test.ps1"
    }
}

Write-Host ""
Write-Host "Done. Quick commands:" -ForegroundColor Green
Write-Host "  WSL VM:     pwsh -File tools\vm\intentos-vm-setup.ps1 -Target WSL -RunTest"
Write-Host "  Sandbox:    pwsh -File tools\vm\intentos-vm-setup.ps1 -Target Sandbox"
Write-Host "  VirtualBox: pwsh -File tools\vm\intentos-vm-setup.ps1 -Target VirtualBox"
Write-Host "  VMware:     pwsh -File tools\vm\intentos-vmware.ps1 -Action Setup"
Write-Host "  Validator:  pwsh -File tools\intentos-vm-validate.ps1"