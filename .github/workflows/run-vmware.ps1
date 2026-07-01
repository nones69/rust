# Launch IntentOS VMware test VM (delegates to tools/vm/intentos-vmware.ps1)
$script = Join-Path $PSScriptRoot "..\..\tools\vm\intentos-vmware.ps1"
if (-not (Test-Path $script)) {
    $script = Join-Path (Split-Path $PSScriptRoot -Parent) "..\tools\vm\intentos-vmware.ps1"
}
& $script -Action Start -Gui