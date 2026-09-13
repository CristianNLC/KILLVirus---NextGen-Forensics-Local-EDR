import os
import json

EXCLUSIONS_FILE = os.path.join("data", "exclusions.json")

def load_exclusions():
    """Carga la lista de rutas o carpetas excluidas del análisis."""
    if not os.path.exists(EXCLUSIONS_FILE):
        return []
    try:
        with open(EXCLUSIONS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return [os.path.normpath(p).lower() for p in data if isinstance(p, str)]
    except Exception:
        return []

def save_exclusions(exclusions_list):
    """Guarda la lista de exclusiones en disco."""
    try:
        os.makedirs(os.path.dirname(EXCLUSIONS_FILE), exist_ok=True)
        with open(EXCLUSIONS_FILE, "w", encoding="utf-8") as f:
            json.dump(exclusions_list, f, indent=2)
        return True
    except Exception:
        return False

def is_path_excluded(filepath, exclusions=None):
    """Verifica si un archivo o directorio cae dentro de una ruta excluida."""
    if exclusions is None:
        exclusions = load_exclusions()

    norm_file = os.path.normpath(os.path.abspath(filepath)).lower()
    for excl in exclusions:
        # Si la exclusión es carpeta y el archivo está dentro de ella
        if norm_file.startswith(excl):
            return True
    return False