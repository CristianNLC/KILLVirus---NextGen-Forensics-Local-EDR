# Changelog

Todas las versiones relevantes de KILLVirus. Formato basado en
[Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y
[Versionado Semántico](https://semver.org/lang/es/).

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
