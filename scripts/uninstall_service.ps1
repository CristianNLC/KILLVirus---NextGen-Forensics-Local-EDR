<#
.SYNOPSIS
    Desinstala el servicio KILLVirusAgent.

.DESCRIPTION
    Atajo de install_service.ps1 -Uninstall. Requiere administrador (UAC).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\uninstall_service.ps1
#>
[CmdletBinding()]
param(
    [string]$DataDir = ""
)

$script = Join-Path $PSScriptRoot "install_service.ps1"
if (-not (Test-Path $script)) {
    throw "No se encontro install_service.ps1 junto a este script."
}

& $script -Uninstall -DataDir $DataDir
exit $LASTEXITCODE
