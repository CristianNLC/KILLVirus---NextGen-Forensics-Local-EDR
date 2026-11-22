# Comprueba que el codigo versionado no contenga secretos y, como refuerzo,
# revisa el binario distribuible. Ejecutar antes de cada release:
#   powershell -ExecutionPolicy Bypass -File scripts\preflight_secret_check.ps1
#
# Nota: el codigo Python viaja comprimido dentro del .exe, asi que la busqueda
# en el binario es best-effort. La revision del codigo fuente es la que manda.

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot

# Solo valores que identifican un secreto real (no nombres de variables ni docs).
$patterns = @(
    'sb_secret_',      # clave secreta de Supabase
    'sbp_',            # personal access token de Supabase
    'APP_USR-',        # access token de Mercado Pago
    'eyJhbGciOi'       # JWT embebido (incluido service_role)
)

$issues = New-Object System.Collections.Generic.List[string]

# --- 1. Binario compilado ---
$exe = Join-Path $root 'dist\KILLVirus_v2.exe'
if (Test-Path $exe) {
    $bytes = [System.IO.File]::ReadAllBytes($exe)
    $latin1 = [System.Text.Encoding]::GetEncoding(28591)  # ISO-8859-1 (compatible con PS 5.1)
    $text = $latin1.GetString($bytes)
    foreach ($p in $patterns) {
        if ($text.Contains($p)) { $issues.Add("BINARIO dist/KILLVirus_v2.exe contiene '$p'") }
    }
} else {
    Write-Host "[i] No existe dist\KILLVirus_v2.exe (se omite el escaneo del binario)." -ForegroundColor DarkGray
}

# --- 2. Archivos versionados ---
$tracked = & git -C $root ls-files
foreach ($rel in $tracked) {
    $rel = $rel.Replace('\', '/')

    if ($rel -eq '.env' -or $rel -eq 'data/license.json' -or $rel -eq 'data/config.json') {
        $issues.Add("VERSIONADO archivo sensible: $rel")
        continue
    }
    if ($rel -like '*.example' -or $rel -like '*.md') { continue }
    if ($rel -notmatch '\.(py|pyw|php|spec|iss|json)$') { continue }

    $full = Join-Path $root $rel
    if (-not (Test-Path -LiteralPath $full)) { continue }

    $content = Get-Content -Raw -LiteralPath $full
    if ([string]::IsNullOrEmpty($content)) { continue }
    foreach ($p in $patterns) {
        if ($content.Contains($p)) { $issues.Add("CODIGO $rel contiene '$p'") }
    }
}

# --- 3. Resultado ---
if ($issues.Count -eq 0) {
    Write-Host "[OK] No se detectaron secretos en el binario ni en el codigo versionado." -ForegroundColor Green
    exit 0
}

Write-Host "[FALLO] Se detectaron posibles secretos:" -ForegroundColor Red
foreach ($i in $issues) { Write-Host "  - $i" -ForegroundColor Yellow }
Write-Host ""
Write-Host "Rota la clave y elimina el valor del codigo antes de publicar." -ForegroundColor Red
exit 1
