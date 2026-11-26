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
    process_evidence: Optional[str] = None  # "handle" | "io"


# Umbrales para la atribución por I/O. Se descartan procesos que escribieron
# demasiado (backups, indexadores) o nada en el intervalo.
IO_MAX_WRITE_BYTES = 8 * 1024 * 1024


def _norm_path(path: str) -> str:
    return os.path.normcase(os.path.abspath(path))


def _is_system_exe(exe: Optional[str]) -> bool:
    """Descarta binarios del sistema para reducir falsos positivos por I/O."""
    if not exe:
        return False
    low = exe.lower()
    windir = os.environ.get("SystemRoot", r"C:\Windows").lower()
    return low.startswith(windir) or "\\program files" in low


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
        # Contadores de I/O de la pasada anterior: permiten atribuir la
        # escritura que ocurrió entre dos sondeos.
        self._io_snapshot: dict[int, dict] = {}

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
        current_io = self._read_io_counters()
        for p in list(self.canary_paths):
            if not os.path.exists(p):
                # Puede haber sido renombrado: buscar archivos canary con nombre similar
                self._alert(p, "deleted", current_io)
                continue
            current = self._file_hash(p)
            with self._lock:
                expected = self._hashes.get(p)
            if expected is None:
                with self._lock:
                    self._hashes[p] = current
            elif current != expected:
                self._alert(p, "modified", current_io)
                with self._lock:
                    self._hashes[p] = current
        self._io_snapshot = current_io

    def _alert(self, path: str, event: str, io_now: Optional[dict] = None) -> None:
        name = os.path.basename(path)
        alert = CanaryAlert(
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            canary_name=name,
            canary_path=os.path.abspath(path),
            event=event,
        )
        # Intentar identificar el proceso responsable (mejor esfuerzo)
        proc_info = self._find_recent_writer(path, io_now)
        if proc_info:
            alert.process_name = proc_info.get("name")
            alert.process_pid = proc_info.get("pid")
            alert.process_exe = proc_info.get("exe")
            alert.process_evidence = proc_info.get("evidence")

        if self.on_alert:
            try:
                self.on_alert(alert)
            except Exception:
                pass

    def _find_recent_writer(
        self, path: str, io_now: Optional[dict] = None
    ) -> Optional[dict]:
        """Atribuye (mejor esfuerzo) el proceso que tocó el canario.

        Dos estrategias, de mayor a menor fiabilidad:
          1. Handle abierto sobre el canario (`Process.open_files()`).
          2. Delta de I/O de escritura entre dos sondeos, solo si hay un único
             candidato plausible.
        Nunca inventa un culpable: si hay ambigüedad devuelve None.
        """
        handles = self._processes_with_open_file(path)
        if handles:
            return {**handles[0], "evidence": "handle"}

        previous = self._io_snapshot
        if not previous:
            return None
        current = io_now if io_now is not None else self._read_io_counters()
        own_pid = os.getpid()
        candidates: list[dict] = []
        for pid, info in current.items():
            before = previous.get(pid)
            if not before or pid == own_pid:
                continue
            delta_bytes = info.get("write_bytes", 0) - before.get("write_bytes", 0)
            delta_count = info.get("write_count", 0) - before.get("write_count", 0)
            if delta_count <= 0 or delta_bytes <= 0:
                continue
            if delta_bytes > IO_MAX_WRITE_BYTES:
                continue
            if _is_system_exe(info.get("exe")):
                continue
            candidates.append({**info, "pid": pid})

        if len(candidates) == 1:
            return {**candidates[0], "evidence": "io"}
        return None

    @staticmethod
    def _read_io_counters() -> dict[int, dict]:
        """Foto de los contadores de I/O por proceso (vacía si no hay psutil)."""
        snapshot: dict[int, dict] = {}
        try:
            import psutil
        except Exception:
            return snapshot
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                counters = proc.io_counters()
                snapshot[proc.info["pid"]] = {
                    "name": proc.info.get("name") or "",
                    "exe": proc.info.get("exe") or "",
                    "write_bytes": counters.write_bytes,
                    "write_count": counters.write_count,
                }
            except Exception:
                # AccesDenied/NoSuchProcess/Zombie: el proceso no es candidato.
                continue
        return snapshot

    @staticmethod
    def _processes_with_open_file(path: str) -> list[dict]:
        """Procesos que mantienen abierto exactamente `path`."""
        target = _norm_path(path)
        found: list[dict] = []
        try:
            import psutil
        except Exception:
            return found
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                for handle in proc.open_files():
                    if _norm_path(handle.path) == target:
                        found.append(
                            {
                                "name": proc.info.get("name") or "",
                                "exe": proc.info.get("exe") or "",
                                "pid": proc.info["pid"],
                            }
                        )
                        break
            except Exception:
                continue
        return found

    def export_alerts(self, alerts: list[CanaryAlert], out_path: str) -> None:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump([asdict(a) for a in alerts], f, indent=2, ensure_ascii=False)
