<#
.SYNOPSIS
    Compila KILLVirus con PyInstaller usando Python 3.13 (con YARA).

.DESCRIPTION
    Python 3.14 aún no tiene wheels de yara-python, así que el release se
    compila con 3.13. El script comprueba dependencias, limpia artefactos
    opcionalmente, ejecuta PyInstaller y muestra tamaño + SHA-256 del .exe.
    Con -Sign delega en scripts\sign_build.ps1.

.PARAMETER PythonExe
    Intérprete a usar. Por defecto busca `py -3.13` y cae a `python`.

.PARAMETER Clean
    Borra build/ y dist/ antes de compilar.

.PARAMETER Sign
    Firma el .exe al terminar (requiere certificado; ver sign_build.ps1).

.PARAMETER SelfSigned
    Con -Sign, crea un certificado de prueba autofirmado si no hay uno.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\build_release.ps1 -Clean

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\build_release.ps1 -Sign -SelfSigned
#>
[CmdletBinding()]
param(
    [string]$PythonExe = "",
    [switch]$Clean,
    [switch]$Sign,
    [switch]$SelfSigned
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Resolve-Python {
    param([string]$Requested)
    if ($Requested) {
        return $Requested
    }
    $launcher = Get-Command py -ErrorAction SilentlyContinue
    if ($launcher) {
        try {
            $resolved = & py -3.13 -c "import sys; print(sys.executable)" 2>$null
            if ($LASTEXITCODE -eq 0 -and $resolved) {
                return $resolved.Trim()
            }
        } catch {
            # Sigue con python del PATH.
        }
    }
    $python = Get-Command python -ErrorAction SilentlyContinue
    if (-not $python) {
        throw "No se encontró Python. Instalá 3.13 o pasá -PythonExe."
    }
    return $python.Source
}

$python = Resolve-Python $PythonExe
Write-Host "Intérprete: $python"
& $python -c "import sys; print('Python', sys.version.split()[0])"

$required = @("PyInstaller", "customtkinter", "psutil", "watchdog", "pystray", "PIL", "requests", "pefile")
foreach ($module in $required) {
    & $python -c "import $module" 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "Falta la dependencia '$module'. Ejecutá: $python -m pip install -r requirements.txt"
    }
}
& $python -c "import yara; print('YARA', yara.__version__)" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "AVISO: yara-python no está instalado; el .exe saldrá sin reglas YARA." -ForegroundColor Yellow
}

if ($Clean) {
    foreach ($path in @("build", "dist")) {
        if (Test-Path $path) {
            Write-Host "Borrando $path\"
            Remove-Item -Recurse -Force $path
        }
    }
}

Write-Host "Compilando packaging\KILLVirus_v2.spec ..."
& $python -m PyInstaller "packaging\KILLVirus_v2.spec" --noconfirm --distpath dist --workpath build
if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller falló con código $LASTEXITCODE. Revisá la salida anterior."
}

$exe = Join-Path $root "dist\KILLVirus_v2.exe"
if (-not (Test-Path $exe)) {
    throw "No se generó $exe"
}

# El .exe se compila con 3.13, pero el desarrollo suele usar 3.14. Un import
# que funciona en 3.14 puede no existir en 3.13 (p. ej. wintypes.HRESULT), y
# eso solo se ve al abrir la interfaz ya empaquetada. Este smoke test importa
# la UI completa con el ejecutable final y falla el build si no arranca.
Write-Host "Comprobando arranque de la interfaz empaquetada (--smoke-test)..."
$smokeDir = Join-Path ([System.IO.Path]::GetTempPath()) ("kv_smoke_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $smokeDir | Out-Null
$previousDataDir = $env:KILLVIRUS_DATA_DIR
$env:KILLVIRUS_DATA_DIR = $smokeDir
try {
    $smoke = Start-Process -FilePath $exe -ArgumentList "--smoke-test" -PassThru
    if (-not $smoke.WaitForExit(90000)) {
        $smoke.Kill()
        throw "El smoke test de la interfaz no terminó en 90 s."
    }
    if ($smoke.ExitCode -ne 0) {
        $errorLog = Join-Path $smokeDir "logs\smoke_test_error.log"
        if (Test-Path $errorLog) {
            Write-Host "--- error de importación ---" -ForegroundColor Red
            Get-Content $errorLog -Tail 40
        }
        throw "El .exe compilado falla al importar la interfaz (--smoke-test, código $($smoke.ExitCode))."
    }
} finally {
    if ($null -eq $previousDataDir) {
        Remove-Item Env:KILLVIRUS_DATA_DIR -ErrorAction SilentlyContinue
    } else {
        $env:KILLVIRUS_DATA_DIR = $previousDataDir
    }
    Remove-Item -Recurse -Force $smokeDir -ErrorAction SilentlyContinue
}
Write-Host "Smoke test de la interfaz: OK" -ForegroundColor Green

$file = Get-Item $exe
$hash = (Get-FileHash $exe -Algorithm SHA256).Hash
Write-Host ""
Write-Host "Compilado: $($file.FullName)" -ForegroundColor Green
Write-Host "  Tamaño : $([math]::Round($file.Length / 1MB, 2)) MB"
Write-Host "  SHA-256: $hash"

if ($Sign) {
    & (Join-Path $PSScriptRoot "sign_build.ps1") -Files $exe -SelfSigned:$SelfSigned
    if ($LASTEXITCODE -ne 0) {
        throw "La firma falló."
    }
}

Write-Host ""
Write-Host "Siguiente paso: compilar el instalador con Inno Setup (installer.iss)."
exit 0
