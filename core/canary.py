"""Canarios antiransomware (PCI - Protección contra Cifrado).

Los canarios son archivos cebo colocados en carpetas sensibles del usuario.
Si un proceso los modifica, renombra o borra, es fuerte indicio de ransomware
en acción. El modulo detecta ese cambio y permite terminar el proceso
responsable.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import asdict, dataclass
from typing import Callable, Optional


# Archivos canario: nombres que ransomware suele intentar cifrar primero.
CANARY_FILES = [
    "KILLVirus_Canary_Documents.txt",
    "KILLVirus_Canary_Photos.txt",
    "KILLVirus_Canary_Backup.txt",
    "KILLVirus_Canary_Important.txt",
]

CANARY_CONTENT = (
    "KILLVirus Canary File\n"
    "Este archivo es un cebo de deteccion de ransomware.\n"
    "Si este archivo ha sido modificado o renombrado sin tu consentimiento,\n"
    "podrias estar sufriendo un ataque de cifrado de archivos.\n"
    "No borres ni edites este archivo manualmente.\n"
)


@dataclass
class CanaryAlert:
    timestamp: str
    canary_name: str
    canary_path: str
    event: str  # "modified", "renamed", "deleted"
    process_name: Optional[str] = None
    process_pid: Optional[int] = None
    process_exe: Optional[str] = None


class CanaryManager:
    """Gestiona archivos canario y su monitoreo."""

    def __init__(
        self,
        watch_dirs: Optional[list[str]] = None,
        on_alert: Optional[Callable[[CanaryAlert], None]] = None,
    ):
        self.watch_dirs = watch_dirs or self._default_watch_dirs()
        self.canary_paths: list[str] = []
        self.on_alert = on_alert
        self._hashes: dict[str, str] = {}
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    # --- ciclo de vida -------------------------------------------------------

    def _default_watch_dirs(self) -> list[str]:
        """Carpetas típicas de usuario donde ransomware actúa primero."""
        dirs = []
        for env in ("USERPROFILE", "APPDATA", "LOCALAPPDATA"):
            base = os.environ.get(env, "")
            if base:
                for sub in ("Documents", "Desktop", "Pictures"):
                    p = os.path.join(base, sub)
                    if os.path.isdir(p):
                        dirs.append(p)
        # Evitar duplicados y rutas internas de KILLVirus
        seen = set()
        out = []
        for d in dirs:
            nd = os.path.normcase(os.path.abspath(d))
            if nd not in seen:
                seen.add(nd)
                out.append(d)
        return out

    def install(self) -> list[str]:
        """Crea los archivos canario en cada carpeta vigilada."""
        installed: list[str] = []
        for d in self.watch_dirs:
            for name in CANARY_FILES:
                p = os.path.join(d, name)
                if not os.path.exists(p):
                    try:
                        with open(p, "w", encoding="utf-8") as f:
                            f.write(CANARY_CONTENT)
                        installed.append(p)
                    except OSError:
                        continue
                self.canary_paths.append(p)
                self._hashes[p] = self._file_hash(p)
        return installed

    def verify(self) -> dict[str, bool]:
        """Verifica integridad de cada canario. Devuelve {path: ok}."""
        results: dict[str, bool] = {}
        for p in self.canary_paths:
            results[p] = self._check_one(p)
        return results

    def _check_one(self, path: str) -> bool:
        if not os.path.exists(path):
            return False
        current = self._file_hash(path)
        with self._lock:
            expected = self._hashes.get(path)
            if expected is None:
                self._hashes[path] = current
                return True
            return current == expected

    @staticmethod
    def _file_hash(path: str) -> str:
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
        except OSError:
            return ""
        return h.hexdigest()

    # --- monitoreo activo ---------------------------------------------------

    def start_monitoring(self, interval: float = 2.0) -> None:
        """Inicia hilo de polling para detectar cambios en canarios."""
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._poll_loop, args=(interval,), name="killvirus-canary", daemon=True
        )
        self._thread.start()

    def stop_monitoring(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    @property
    def is_monitoring(self) -> bool:
        """True si el hilo de polling de canarios está activo."""
        return bool(self._thread and self._thread.is_alive())

    def _poll_loop(self, interval: float) -> None:
        while not self._stop.is_set():
            try:
                self._scan_once()
            except Exception:
                pass
            self._stop.wait(interval)

    def _scan_once(self) -> None:
        for p in list(self.canary_paths):
            if not os.path.exists(p):
                # Puede haber sido renombrado: buscar archivos canary con nombre similar
                self._alert(p, "deleted")
                continue
            current = self._file_hash(p)
            with self._lock:
                expected = self._hashes.get(p)
            if expected is None:
                with self._lock:
                    self._hashes[p] = current
            elif current != expected:
                self._alert(p, "modified")
                with self._lock:
                    self._hashes[p] = current

    def _alert(self, path: str, event: str) -> None:
        name = os.path.basename(path)
        alert = CanaryAlert(
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            canary_name=name,
            canary_path=os.path.abspath(path),
            event=event,
        )
        # Intentar identificar el proceso responsable (mejor esfuerzo)
        proc_info = self._find_recent_writer(path)
        if proc_info:
            alert.process_name = proc_info.get("name")
            alert.process_pid = proc_info.get("pid")
            alert.process_exe = proc_info.get("exe")

        if self.on_alert:
            try:
                self.on_alert(alert)
            except Exception:
                pass

    def _find_recent_writer(self, path: str) -> Optional[dict]:
        """Punto de extensión para identificar al escritor (USN/ETW).

        Obtener el proceso real requiere el diario USN o ETW, fuera del alcance
        de este módulo. Se devuelve None para que la UI lo indique como
        desconocido en lugar de inventar un culpable.
        """
        return None

    def export_alerts(self, alerts: list[CanaryAlert], out_path: str) -> None:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump([asdict(a) for a in alerts], f, indent=2, ensure_ascii=False)
