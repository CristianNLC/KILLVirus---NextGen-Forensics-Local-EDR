"""Lógica única de exclusión de rutas.

Antes cada capa decidía por su cuenta si una ruta estaba excluida (la UI con
`startswith(ruta + sep)` y `core/whitelist.py` con `startswith(ruta)`, que
excluía de más: `C:\\foo` también cubría `C:\\foobar`).

Aquí se compara por componentes de ruta, con `normcase`/`normpath`, para que
`C:\\Temp` excluya `C:\\Temp\\x.exe` pero no `C:\\Temporal\\x.exe`.
"""

import os


def normalize_path(path):
    """Normaliza para comparar en Windows (absoluta, sin `.`/`..`, sin distinguir mayúsculas)."""
    return os.path.normcase(os.path.normpath(os.path.abspath(path)))


def parse_exclusions(text):
    """Convierte el contenido del cuadro de texto de la UI en una lista limpia."""
    if not text:
        return []
    return [line.strip() for line in text.splitlines() if line.strip()]


def is_excluded(filepath, exclusions):
    """True si `filepath` es una exclusión o está dentro de una carpeta excluida."""
    if not filepath or not exclusions:
        return False

    try:
        target = normalize_path(filepath)
    except (OSError, ValueError):
        return False

    for raw in exclusions:
        if not isinstance(raw, str) or not raw.strip():
            continue
        try:
            base = normalize_path(raw)
        except (OSError, ValueError):
            continue
        prefix = base if base.endswith(os.sep) else base + os.sep
        if target == base or target.startswith(prefix):
            return True
    return False
