# Seguridad de KILLVirus

KILLVirus funciona **100% local**: no requiere cuenta, licencia, servidor ni
conexión a internet. No hay backend, no hay base de datos de clientes y el
código no contiene claves de terceros.

> Estado: la capa de licencias PRO y facturación (Supabase + Mercado Pago) fue
> eliminada por completo. Este documento queda como registro de la limpieza y
> como checklist para futuros releases.

---

## 1. Servicios externos que hay que dar de baja

Aunque el proyecto ya no los usa, las credenciales siguen existiendo y estuvieron
expuestas en el historial de git. Hay que revocarlas igualmente:

| Servicio | Acción | Motivo |
|---|---|---|
| Supabase | **Revocar la secret key** y, si no se usará más, pausar/eliminar el proyecto | `sb_secret_...` estuvo hardcodeada en `core/licensing.py` (commit `88f1eba`) y permitía leer/escribir toda la tabla de licencias |
| Mercado Pago | **Revocar el access token** | Estuvo en `.env` local y se usó con verificación TLS desactivada |
| VirusTotal | **Revocar la API key** | Estaba en texto plano en `data/config.json` del equipo |

### `.env` local

Ya no se lee desde ningún punto del código. Bórralo de tu equipo:

```powershell
Remove-Item .env
```

---

## 2. Purga del historial de git (recomendado, destructivo)

Una vez revocadas las claves deja de ser urgente, pero el secreto no debería
quedar en el historial. Coordina con quien tenga clones: reescribe los hashes.

```powershell
pip install git-filter-repo

# Sacar archivos de licencia/config del historial
git filter-repo --path data/license.json --invert-paths
git filter-repo --path core/licensing.py --invert-paths
git filter-repo --path core/license_manager.py --invert-paths

# Reemplazar el secreto por un marcador (coloca el valor exacto en la 1ª columna)
@"
<clave-secreta-filtrada>==>***REMOVED***
"@ | Set-Content replacements.txt
git filter-repo --replace-text replacements.txt
Remove-Item replacements.txt

git remote add origin <url>
git push --force --all
git push --force --tags
```

Si prefieres no reescribir historia, con las claves revocadas es suficiente.

---

## 3. Verificación antes de cada release

```powershell
powershell -ExecutionPolicy Bypass -File scripts\preflight_secret_check.ps1
```

Falla si encuentra `sb_secret_`, `sbp_`, `APP_USR-` o un JWT embebido en el
código versionado. La revisión del código es la que manda; el escaneo del `.exe`
es best-effort porque el bytecode viaja comprimido.

Comprobación rápida adicional:

```powershell
git ls-files | Select-String -Pattern '(^|/)\.env$|config\.json|license\.json'
# No debe listar archivos con datos reales
```

---

## 4. Reglas para no repetirlo

1. **Nunca** una clave en el código, ni "temporal" ni como fallback para el
   `.exe`. Si hace falta, va en el servidor, nunca en el cliente.
2. `core/license_manager.py` y `core/licensing.py` ya no existen; no reintroducir
   lógica de licencias que necesite red.
3. Los `.spec` no empaquetan `core/` ni `ui/` como datos: no se distribuye código
   fuente dentro del `.exe`.
4. `upx=False`: UPX es un packer y dispara heurísticas de antivirus (incluido
   Defender) contra tu propio instalador.
5. El instalador excluye `config.json` y `exclusions.json` para no repartir
   configuración personal del desarrollador.
6. Activa `gitleaks` como pre-commit cuando empieces a usar remotos:
   `gitleaks protect --staged --redact`.
7. Firma el `.exe` y el instalador con un certificado de code signing antes de
   publicar (pendiente: requiere certificado OV/EV).

---

## 5. Nota sobre VirusTotal (opcional)

La consulta a VirusTotal es una función opcional que el usuario activa con su
propia API key, guardada en `data/config.json`. Ese archivo está en `.gitignore`
y se excluye del instalador. Si no usas la función, deja la clave vacía.

El escaneo de disco, YARA, análisis PE, cuarentena, RAM y persistencia funcionan
sin conexión y sin ninguna clave.
