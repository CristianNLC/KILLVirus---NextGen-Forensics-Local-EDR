# Changelog

Todas las versiones relevantes de KILLVirus. Formato basado en
[Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y
[Versionado Semántico](https://semver.org/lang/es/).

## [2.3.0] - 2026-11-26

### Añadido
- **Cuarentena cifrada (DPAPI):** el contenido aislado se guarda cifrado con
  `CryptProtectData` en ámbito de máquina, así que la interfaz (usuario) y el
  servicio (SYSTEM) pueden restaurarlo. El archivo en cuarentena ya no es
  ejecutable ni copiable directamente; los aislamientos antiguos en claro se
  siguen restaurando por compatibilidad.
- **Atribución del escritor de canarios:** al modificarse un canario se busca
  primero un proceso con el archivo abierto (`open_files`) y, si no lo hay, un
  único candidato por delta de I/O de escritura. Si hay ambigüedad no se culpa a
  nadie y la UI lo muestra como desconocido. La evidencia (`handle` / `I/O`) se
  muestra junto al proceso.
- `scripts/build_release.ps1`: build reproducible con Python 3.13, comprobación
  de dependencias, tamaño y SHA-256 del ejecutable.
- `scripts/sign_build.ps1`: firma Authenticode con `signtool` (almacén, `.pfx`
  o certificado autofirmado de pruebas) y verificación posterior.
- Specs de PyInstaller anclados a la raíz del proyecto: el build funciona desde
  cualquier directorio y detecta el entrypoint correcto.
- `scripts/selftest.py`: verifica cifrado, metadatos y restauración de la
  cuarentena.

### Cambiado
- La vista de cuarentena marca los elementos cifrados con 🔒 y el detalle
  muestra el estado de protección.
- Versión 2.3.0.

### Corregido
- **Autoprotección (grave):** `icacls /T` aplicaba el permiso heredable
  `(OI)(CI)F` también a los archivos; al quitar la herencia, los archivos
  existentes quedaban con una DACL vacía (ilegibles, incluida
  `signatures.db`). Ahora se hace en dos pasadas: control total explícito sobre
  archivos y carpetas, y permisos heredables solo en las carpetas. Hay un test
  que verifica que los archivos siguen legibles tras endurecer.

## [2.2.0] - 2026-11-23

### Añadido
- `core/signatures/store.py`: `SqliteStore` con WAL, `busy_timeout` y lock
  interno; la interfaz y el servicio pueden compartir la misma base sin
  errores de hilo ni de bloqueo.
- `core/agent.py`: agente de protección headless (watcher, canarios, monitor de
  procesos) con cola de cuarentena, heartbeat en `data/agent_status.json` y
  watchdog que reinicia componentes caídos.
- `core/winservice.py`: host de servicio de Windows con `ctypes`
  (`StartServiceCtrlDispatcherW`), sin pywin32 ni dependencias externas.
- `core/service_control.py`: instalación/desinstalación/estado vía `sc.exe`,
  recuperación automática del servicio y elevación por UAC.
- `core/autoprotect.py`: ACLs endurecidas con `icacls` (SIDs, sin herencia) y
  manifiesto de integridad SHA-256 del código y del ejecutable.
- `app.pyw`: modos `--agent`, `--service`, `--install-service`,
  `--uninstall-service`, `--start-service`, `--stop-service`,
  `--service-status`, `--harden`, `--integrity-write` e `--integrity-verify`.
- Vista **Servicio y Autoprotección** con estado del SCM, heartbeat del agente,
  botones de instalación, ACLs e integridad.
- `tests/` para agente, servicio, autoprotección, canarios, AMSI, cuarentena y
  store (73 pruebas).
- `scripts/install_service.ps1` y `scripts/uninstall_service.ps1`.
- Instalador Inno Setup: tarea opcional de servicio y desinstalación limpia.

### Corregido
- `quit_app()` fallaba con `AttributeError` al cerrar la ventana (referencias
  obsoletas a `live_handler`/`observer`).
- Layout de la barra lateral: etiquetas y botones se superponían en las mismas
  filas; ahora hay un espaciador real y filas únicas.
- Vista de canarios: dos filas con `weight=1` que descuadraban las tablas.
- Carpetas de canarios duplicadas (`Pictures` dos veces).

## [2.1.0] - 2026-11-20

### Añadido
- `core/paths.py`: rutas absolutas de datos; en desarrollo usa el repo y
  empaquetado usa `%LOCALAPPDATA%\KILLVirus`, con siembra de firmas y reglas.
- `core/scan_engine.py`: motor de veredicto único compartido por escaneo de
  disco y protección en vivo (hash > YARA > heurística/PE).
- `core/logging_setup.py`: log rotativo en `logs/killvirus.log` y captura de
  excepciones no controladas.
- `core/exclusions.py`: lógica única de exclusiones (corrige el falso positivo
  de prefijos tipo `C:\foo` vs `C:\foobar`).
- Instancia única real (mutex de Windows) para evitar dos motores en vivo.
- `tests/` con pytest y workflow de CI en Windows.
- `LICENSE` (MIT), `CHANGELOG.md` y `pyproject.toml` con configuración de
  ruff/pytest.

### Cambiado
- Actualizador de firmas migrado a la ThreatFox Community API con `Auth-Key`
  (las exportaciones CSV respondían HTTP 410) y guardado atómico.
- La firma Authenticode ya no indulta detecciones: solo descarta heurísticas
  débiles de binarios con firma embebida válida.
- Protección en vivo con cola y hilo trabajador (sin sleeps en el callback de
  watchdog), deduplicación y escucha de cierre/renombrado.
- Empaquetado: un único `KILLVirus.spec`, `upx=False` e instalador sin estado
  local del desarrollador.
- "KILLVirus PRO" → "KILLVirus" en instalador y bandeja del sistema.

### Eliminado
- Capa PRO: Supabase, Mercado Pago, licencias y modal de pago.
- `core/whitelist.py` (sin uso; las exclusiones viven en `config.json`).
- `signatures.json` duplicado en la raíz y artefactos de escaneo versionados.
- Hash de archivo vacío en la base de firmas (falso positivo en `.bat` vacíos).

### Corregido
- `config.json` con BOM ya no rompe la carga de claves ni exclusiones.
- Auditoría de persistencia: un hash malicioso ya no se ignora por estar
  firmado; además se resuelve la ruta real del ejecutable.
- Autorun con `os.getcwd()` y rutas relativas en equipos empaquetados.

## [2.0.0] - 2025-09-20

- Versión inicial publicada: escáner, cuarentena, YARA, VirusTotal, RAM y
  persistencia.
