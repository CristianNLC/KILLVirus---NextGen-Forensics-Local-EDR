<#
.SYNOPSIS
    Compila el instalador de KILLVirus con Inno Setup.

.DESCRIPTION
    Verifica que exista dist\KILLVirus_v2.exe y que su versión coincida con la
    del installer.iss, busca ISCC.exe (Inno Setup 6.3+ o 7) y compila
    dist_installer\KILLVirus_v2_Setup.exe. Muestra tamaño y SHA-256.

.PARAMETER Sign
    Firma el instalador al terminar con scripts\sign_build.ps1.

.PARAMETER Thumbprint
    Huella del certificado a usar para firmar (se pasa a sign_build.ps1).

.PARAMETER SelfSigned
    Firma con un certificado autofirmado de pruebas (se pasa a sign_build.ps1).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\build_installer.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\build_installer.ps1 -Sign -SelfSigned
#>
param(
    [switch]$Sign,
    [string]$Thumbprint = "",
    [switch]$SelfSigned
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Find-ISCC {
    # 1) Registro: instalación actual (Inno 6 o 7).
    $keys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup*"
    )
    foreach ($key in $keys) {
        $entry = Get-ItemProperty $key -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -like "Inno Setup*" -and $_.InstallLocation } |
            Sort-Object DisplayVersion -Descending |
            Select-Object -First 1
        if ($entry) {
            $candidate = Join-Path $entry.InstallLocation "ISCC.exe"
            if (Test-Path $candidate) { return $candidate }
        }
    }
    # 2) Rutas habituales.
    $paths = @(
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
        "${env:LOCALAPPDATA}\Programs\Inno Setup 6\ISCC.exe",
        "${env:ProgramFiles(x86)}\Inno Setup 7\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 7\ISCC.exe",
        "${env:LOCALAPPDATA}\Programs\Inno Setup 7\ISCC.exe"
    )
    foreach ($path in $paths) {
        if (Test-Path $path) { return $path }
    }
    # 3) PATH.
    $cmd = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

$iscc = Find-ISCC
if (-not $iscc) {
    throw "No se encontró Inno Setup (ISCC.exe). Instalalo con 'winget install JRSoftware.InnoSetup'."
}
Write-Host "Inno Setup: $iscc"

$exe = Join-Path $root "dist\KILLVirus_v2.exe"
if (-not (Test-Path $exe)) {
    throw "Falta dist\KILLVirus_v2.exe. Ejecutá primero scripts\build_release.ps1."
}

$exeVersion = (Get-Item $exe).VersionInfo.FileVersion
$appVersion = (Select-String -Path (Join-Path $root "installer.iss") -Pattern '^AppVersion=(.+)$').Matches[0].Groups[1].Value.Trim()
Write-Host "Versión del .exe : $exeVersion"
Write-Host "Versión del .iss : $appVersion"
if ($exeVersion -ne $appVersion) {
    throw "La versión del ejecutable ($exeVersion) no coincide con installer.iss ($appVersion). Recompilá con build_release.ps1."
}

Write-Host "Compilando installer.iss ..."
& $iscc (Join-Path $root "installer.iss")
if ($LASTEXITCODE -ne 0) {
    throw "ISCC falló con código $LASTEXITCODE"
}

$setup = Join-Path $root "dist_installer\KILLVirus_v2_Setup.exe"
if (-not (Test-Path $setup)) {
    throw "ISCC terminó pero no se generó $setup"
}
$file = Get-Item $setup
Write-Host ""
Write-Host "Instalador: $setup"
Write-Host ("  Tamaño : {0:N2} MB" -f ($file.Length / 1MB))
Write-Host "  SHA-256: $((Get-FileHash $setup -Algorithm SHA256).Hash)"
Write-Host "  Versión: $($file.VersionInfo.FileVersion)"

if ($Sign) {
    $signArgs = @{ Files = @($setup) }
    if ($Thumbprint) { $signArgs.Thumbprint = $Thumbprint }
    if ($SelfSigned) { $signArgs.SelfSigned = $true }
    if (-not $Thumbprint -and -not $SelfSigned) {
        throw "Indicá -Thumbprint o -SelfSigned para firmar el instalador."
    }
    & (Join-Path $PSScriptRoot "sign_build.ps1") @signArgs
    if ($LASTEXITCODE -ne 0) {
        throw "La firma del instalador falló con código $LASTEXITCODE"
    }
}

exit 0
