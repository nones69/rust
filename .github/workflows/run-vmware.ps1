Write-Host "Preparing to launch VMware..."

# Replace this with the actual path to your VMX file and VMware executable
$VMX_PATH = "C:\Virtual Machines\IntentKernel\IntentKernel.vmx"
$VMWARE_EXE = "C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"

if (Test-Path $VMWARE_EXE) {
    Write-Host "Starting VM..."
    & $VMWARE_EXE start $VMX_PATH
} else {
    Write-Warning "VMware vmrun.exe not found at $VMWARE_EXE"
    Write-Host "Please ensure VMware is installed or update the script path."
}