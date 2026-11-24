<#
.SYNOPSIS
    Instala KILLVirusAgent como servicio de Windows (agente headless).

.DESCRIPTION
    Prefiere el ejecutable empaquetado en dist\; si no existe, usa el Python
    del sistema y app.pyw. Registra el servicio con sc.exe, configura
    recuperacion automatica y lo arranca. Requiere administrador (UAC).

.PARAMETER DataDir
    Carpeta de datos compartida entre la interfaz y el servicio.
    Por defecto: %LOCALAPPDATA%\KILLVirus

.PARAMETER Uninstall
    Detiene y elimina el servicio en lugar de instalarlo.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\install_service.ps1
#>
[CmdletBinding()]
param(
    [string]$DataDir = "",
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

# --- elevacion automatica ----------------------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
$isAdmin = $principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) {
    Write-Host "Se requieren privilegios de administrador: relanzando con UAC..." -ForegroundColor Yellow
    $arguments = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", "`"$PSCommandPath`""
    )
    if ($DataDir) { $arguments += @("-DataDir", "`"$DataDir`"") }
    if ($Uninstall) { $arguments += "-Uninstall" }
    Start-Process powershell -Verb RunAs -ArgumentList ($arguments -join " ")
    exit 0
}

# --- localizar ejecutable ----------------------------------------------------
$exe = Join-Path $root "dist\KILLVirus_v2.exe"
if (-not (Test-Path $exe)) { $exe = Join-Path $root "dist\KILLVirus.exe" }

if (-not $DataDir) { $DataDir = Join-Path $env:LOCALAPPDATA "KILLVirus" }

if (Test-Path $exe) {
    $command = "`"$exe`""
} else {
    $python = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $python) {
        throw "No se encontro python.exe ni un ejecutable empaquetado en dist\."
    }
    $command = "`"$python`" `"$root\app.pyw`""
}

if ($Uninstall) {
    Write-Host "Desinstalando KILLVirusAgent..."
    & cmd /c "$command --uninstall-service"
    $code = $LASTEXITCODE
    if ($code -eq 0) {
        Write-Host "Servicio eliminado." -ForegroundColor Green
    } else {
        Write-Host "La desinstalacion devolvio codigo $code." -ForegroundColor Red
    }
    exit $code
}

Write-Host "Instalando KILLVirusAgent..."
Write-Host "  Datos: $DataDir"
& cmd /c "$command --install-service --data-dir `"$DataDir`""
$code = $LASTEXITCODE

if ($code -eq 0) {
    Write-Host "Servicio instalado y en ejecucion." -ForegroundColor Green
    Write-Host "  sc.exe query KILLVirusAgent"
} else {
    Write-Host "La instalacion devolvio codigo $code." -ForegroundColor Red
    Write-Host "Revisa $DataDir\logs\killvirus.log" -ForegroundColor Yellow
}
exit $code
