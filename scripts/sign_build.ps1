<#
.SYNOPSIS
    Firma binarios con Authenticode y verifica la firma.

.DESCRIPTION
    Usa signtool.exe si está disponible (Windows SDK). Si no, cae a
    Set-AuthenticodeSignature, incluido en PowerShell, para no bloquear el
    flujo en equipos sin SDK.

    Modos:
      * -Thumbprint <hash>   usa un certificado del almacén del usuario.
      * -PfxPath <ruta>      usa un .pfx (+ -PfxPassword opcional).
      * -SelfSigned          crea/usar un certificado de PRUEBA autofirmado.
                            No sirve para distribución: otros equipos y
                            SmartScreen no lo reconocen como de confianza.

    La marca de tiempo es RFC3161 por defecto (DigiCert). Sin timestamp, la
    firma caduca cuando caduca el certificado.

.PARAMETER Files
    Archivos a firmar. Por defecto dist\KILLVirus_v2.exe.

.PARAMETER Thumbprint
    Huella SHA-1 del certificado en Cert:\CurrentUser\My.

.PARAMETER PfxPath
    Ruta al .pfx/.p12.

.PARAMETER PfxPassword
    Contraseña del .pfx (opcional).

.PARAMETER SelfSigned
    Crea un certificado autofirmado de pruebas si no se indicó otro.

.PARAMETER TimestampUrl
    Servidor de sellado de tiempo RFC3161.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\sign_build.ps1 -SelfSigned

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\sign_build.ps1 -Thumbprint ABC123... -Files dist\KILLVirus_v2.exe,dist_installer\KILLVirus_v2_Setup.exe
#>
[CmdletBinding(DefaultParameterSetName = "Store")]
param(
    [string[]]$Files = @("dist\KILLVirus_v2.exe"),
    [Parameter(ParameterSetName = "Store")]
    [string]$Thumbprint = "",
    [Parameter(ParameterSetName = "Pfx")]
    [string]$PfxPath = "",
    [Parameter(ParameterSetName = "Pfx")]
    [string]$PfxPassword = "",
    [switch]$SelfSigned,
    [string]$TimestampUrl = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Find-SignTool {
    $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }
    $kits = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin",
        "$env:ProgramFiles\Windows Kits\10\bin"
    )
    foreach ($kit in $kits) {
        if (-not (Test-Path $kit)) { continue }
        $candidate = Get-ChildItem -Path $kit -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match "\\x64\\signtool\.exe$" } |
            Sort-Object FullName -Descending |
            Select-Object -First 1
        if ($candidate) {
            return $candidate.FullName
        }
    }
    return $null
}

$signtool = Find-SignTool
if ($signtool) {
    Write-Host "Firma con signtool: $signtool"
} else {
    Write-Host "signtool no encontrado; se usará Set-AuthenticodeSignature." -ForegroundColor Yellow
}

$existing = @()
foreach ($file in $Files) {
    $full = if ([System.IO.Path]::IsPathRooted($file)) { $file } else { Join-Path $root $file }
    if (-not (Test-Path $full)) {
        throw "No existe el archivo a firmar: $full"
    }
    $existing += $full
}

if ($SelfSigned -and -not $Thumbprint -and -not $PfxPath) {
    $subject = "CN=KILLVirus (pruebas), O=KILLVirus, C=AR"
    $cert = Get-ChildItem Cert:\CurrentUser\My |
        Where-Object { $_.Subject -eq $subject -and $_.HasPrivateKey } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1
    if (-not $cert) {
        Write-Host "Creando certificado autofirmado de pruebas..."
        $cert = New-SelfSignedCertificate `
            -Type CodeSigningCert `
            -Subject $subject `
            -KeyUsage DigitalSignature `
            -KeyAlgorithm RSA `
            -KeyLength 3072 `
            -HashAlgorithm SHA256 `
            -CertStoreLocation "Cert:\CurrentUser\My" `
            -NotAfter (Get-Date).AddYears(2)
    }
    $Thumbprint = $cert.Thumbprint
    $cerPath = Join-Path $root "dist\KILLVirus_TestCert.cer"
    New-Item -ItemType Directory -Force -Path (Split-Path $cerPath) | Out-Null
    Export-Certificate -Cert $cert -FilePath $cerPath | Out-Null
    Write-Host "Certificado de PRUEBA: $Thumbprint" -ForegroundColor Yellow
    Write-Host "  Exportado a: $cerPath"
    Write-Host "  NO usar para distribución: solo valida el flujo de firma." -ForegroundColor Yellow
}

# Certificado para el fallback de PowerShell.
$psCert = $null
if (-not $signtool) {
    if ($PfxPath) {
        $pfxFull = if ([System.IO.Path]::IsPathRooted($PfxPath)) { $PfxPath } else { Join-Path $root $PfxPath }
        $psCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 `
            -ArgumentList @($pfxFull, $PfxPassword)
    } elseif ($Thumbprint) {
        $psCert = Get-Item "Cert:\CurrentUser\My\$Thumbprint"
    }
    if (-not $psCert) {
        throw "No se pudo cargar el certificado para Set-AuthenticodeSignature."
    }
}

if ($PfxPath) {
    $pfxFull = if ([System.IO.Path]::IsPathRooted($PfxPath)) { $PfxPath } else { Join-Path $root $PfxPath }
    $signArgs = @("sign", "/fd", "SHA256", "/f", $pfxFull)
    if ($PfxPassword) {
        $signArgs += @("/p", $PfxPassword)
    }
} elseif ($Thumbprint) {
    $signArgs = @("sign", "/fd", "SHA256", "/sha1", $Thumbprint)
} else {
    throw "Indicá -Thumbprint, -PfxPath o -SelfSigned."
}

if ($signtool) {
    $signArgs += @("/tr", $TimestampUrl, "/td", "SHA256")
    $signArgs += $existing
    Write-Host "Firmando $($existing.Count) archivo(s) con signtool..."
    & $signtool @signArgs
    if ($LASTEXITCODE -ne 0) {
        throw "signtool sign falló con código $LASTEXITCODE"
    }
} else {
    foreach ($file in $existing) {
        Write-Host "Firmando con PowerShell: $file"
        $result = Set-AuthenticodeSignature -FilePath $file -Certificate $psCert `
            -TimestampServer $TimestampUrl -HashAlgorithm SHA256
        if ($result.Status -notin @("Valid", "UnknownError")) {
            throw "Set-AuthenticodeSignature falló: $($result.Status) $($result.StatusMessage)"
        }
    }
}

$failed = 0
foreach ($file in $existing) {
    if ($signtool) {
        & $signtool verify /pa /v $file | Out-Null
        $ok = ($LASTEXITCODE -eq 0)
        $label = "Firma válida"
    } else {
        $sig = Get-AuthenticodeSignature $file
        $ok = ($sig.Status -eq "Valid")
        $label = "Firma válida"
        if (-not $ok -and $SelfSigned -and $sig.SignerCertificate -and
            $sig.SignerCertificate.Thumbprint -eq $Thumbprint) {
            # Una autofirmada nunca será "Valid" fuera del almacén de confianza:
            # basta con comprobar que la firma existe y es del certificado usado.
            $ok = $true
            $label = "Firma autofirmada presente (no confiable en otros equipos)"
        }
    }
    if ($ok) {
        Write-Host "${label}: $file" -ForegroundColor Green
    } else {
        Write-Host "Firma NO válida: $file" -ForegroundColor Red
        $failed++
    }
}
exit $failed
