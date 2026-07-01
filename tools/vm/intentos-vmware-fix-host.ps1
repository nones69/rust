#Requires -RunAsAdministrator
# Repair VMware Workstation host networking (NAT + DHCP).
$ErrorActionPreference = "Continue"

Write-Host "── VMware host network repair" -ForegroundColor Cyan

foreach ($name in @("VMnetuserif", "VMnetDHCP", "VMware NAT Service")) {
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if (-not $svc) { continue }
    if ($svc.StartType -eq "Disabled") {
        Set-Service -Name $name -StartupType Manual
    }
    if ($svc.Status -ne "Running") {
        Write-Host "Starting $name..."
        Start-Service -Name $name -ErrorAction SilentlyContinue
    }
}

Set-Service VMnetDHCP -StartupType Automatic -ErrorAction SilentlyContinue
Set-Service "VMware NAT Service" -StartupType Automatic -ErrorAction SilentlyContinue

$vmnet8 = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "VMnet8" }
if ($vmnet8) {
    Write-Host "Resetting $($vmnet8.Name)..."
    Disable-NetAdapter -Name $vmnet8.Name -Confirm:$false -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Enable-NetAdapter -Name $vmnet8.Name -Confirm:$false -ErrorAction SilentlyContinue
}

Write-Host ""
Get-Service VMnetuserif, VMnetDHCP, "VMware NAT Service" -ErrorAction SilentlyContinue |
    Format-Table Name, Status, StartType -AutoSize

$nat = Get-Service "VMware NAT Service" -ErrorAction SilentlyContinue
if ($nat -and $nat.Status -ne "Running") {
    Write-Host "NAT still stopped — bridged VM networking will still work." -ForegroundColor Yellow
    Write-Host "To fix NAT: VMware Workstation -> Edit -> Virtual Network Editor -> Restore Defaults" -ForegroundColor Yellow
}