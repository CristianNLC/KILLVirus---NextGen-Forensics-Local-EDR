"""
Rutas de datos de KILLVirus.

Reglas:
  * Nunca depender de os.getcwd(): si el .exe se abre desde el menú contextual
    o desde un acceso directo, el cwd puede ser cualquier carpeta y el programa
    se quedaría sin firmas, sin reglas YARA y con la cuarentena en un sitio
    aleatorio.
  * En desarrollo se usan las carpetas del proyecto (misma experiencia que
    antes). Empaquetado, se usa %LOCALAPPDATA%\\KILLVirus, que siempre es
    escribible por el usuario aunque el .exe esté en Program Files.
  * En el primer arranque se copian las firmas y reglas YARA que vienen con el
    instalador ("seed") al directorio de datos del usuario.
"""

import os
import sys
import shutil

APP_NAME = "KILLVirus"
IS_FROZEN = bool(getattr(sys, "frozen", False))


def _app_base_dir() -> str:
    if IS_FROZEN:
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _user_data_dir() -> str:
    base = os.environ.get("LOCALAPPDATA")
    if not base:
        base = os.path.join(os.path.expanduser("~"), "AppData", "Local")
    return os.path.join(base, APP_NAME)


BASE_DIR = _app_base_dir()

# Datos de solo lectura que trae el instalador (o el repo en desarrollo).
BUNDLE_DATA_DIR = os.path.join(BASE_DIR, "data")

# Directorio escribible de ejecución.
if IS_FROZEN:
    RUNTIME_DIR = _user_data_dir()
else:
    RUNTIME_DIR = BASE_DIR

DATA_DIR = os.path.join(RUNTIME_DIR, "data")
QUARANTINE_DIR = os.path.join(RUNTIME_DIR, "cuarentena")
REPORTS_DIR = os.path.join(RUNTIME_DIR, "reportes")
LOG_DIR = os.path.join(RUNTIME_DIR, "logs")

CONFIG_FILE = os.path.join(DATA_DIR, "config.json")
SIGNATURES_FILE = os.path.join(DATA_DIR, "signatures.json")
RULES_FILE = os.path.join(DATA_DIR, "rules.yar")
EXCLUSIONS_FILE = os.path.join(DATA_DIR, "exclusions.json")

# Archivos que se copian desde el bundle si faltan en el directorio escribible.
SEED_FILES = ("signatures.json", "rules.yar")

_RUNTIME_DIRS = (DATA_DIR, QUARANTINE_DIR, REPORTS_DIR, LOG_DIR)


def ensure_runtime_dirs() -> None:
    """Crea las carpetas de ejecución si no existen (nunca lanza excepción)."""
    for directory in _RUNTIME_DIRS:
        try:
            os.makedirs(directory, exist_ok=True)
        except Exception:
            pass


def seed_data_files() -> None:
    """Copia firmas/reglas iniciales del bundle si aún no hay copia local."""
    if os.path.normcase(os.path.abspath(BUNDLE_DATA_DIR)) == os.path.normcase(os.path.abspath(DATA_DIR)):
        return  # En desarrollo ya son la misma carpeta.

    for name in SEED_FILES:
        src = os.path.join(BUNDLE_DATA_DIR, name)
        dst = os.path.join(DATA_DIR, name)
        try:
            if os.path.isfile(src) and not os.path.exists(dst):
                shutil.copy2(src, dst)
        except Exception:
            pass


def init_app() -> None:
    """Inicializa el almacenamiento local. Llamar al arrancar la aplicación."""
    ensure_runtime_dirs()
    seed_data_files()


def is_inside_runtime_dir(filepath: str) -> bool:
    """True si la ruta está dentro de cuarentena/reportes (no debe reescanearse)."""
    try:
        target = os.path.normcase(os.path.abspath(filepath))
    except Exception:
        return False
    for directory in (QUARANTINE_DIR, REPORTS_DIR):
        base = os.path.normcase(os.path.abspath(directory))
        if target == base or target.startswith(base + os.sep):
            return True
    return False
