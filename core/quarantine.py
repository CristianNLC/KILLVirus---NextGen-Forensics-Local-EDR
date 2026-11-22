import os
import json
import shutil
from datetime import datetime

from core.paths import QUARANTINE_DIR, ensure_runtime_dirs


def isolate_file(filepath, reason=None, sha256=None):
    """Mueve un archivo a cuarentena y guarda su metadata.

    Retorna la ruta del archivo aislado o None si no se pudo mover.
    """
    try:
        ensure_runtime_dirs()
        filename = os.path.basename(filepath)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        dest_path = os.path.join(QUARANTINE_DIR, f"{filename}_{timestamp}.quarantine")
        # Evita colisiones si el mismo nombre se aísla dos veces en el mismo segundo.
        counter = 1
        while os.path.exists(dest_path):
            dest_path = os.path.join(
                QUARANTINE_DIR, f"{filename}_{timestamp}_{counter}.quarantine"
            )
            counter += 1

        meta_path = dest_path + ".meta"
        meta = {
            "original_path": os.path.abspath(filepath),
            "date": timestamp,
            "reason": reason or "Detección heurística",
            "sha256": sha256 or "",
        }
        with open(meta_path, "w", encoding="utf-8") as meta_file:
            json.dump(meta, meta_file, indent=2)

        try:
            shutil.move(filepath, dest_path)
        except Exception:
            # No dejar metadata huérfana si el movimiento falla.
            try:
                os.remove(meta_path)
            except OSError:
                pass
            return None

        return dest_path
    except Exception:
        return None
