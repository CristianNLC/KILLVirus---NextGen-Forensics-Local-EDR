"""Monitor de creación de procesos (alternativa ligera a ETW).

Hace polling de procesos activos y detecta los que aparecen nuevos.
Si un proceso nuevo coincide con una firma de malware, se reporta.
No requiere drivers ni ETW: funciona con psutil en cualquier Windows.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Callable, Optional

import psutil

from core.signatures import SignatureStore, SignatureEntry
from core.scanner import calculate_sha256


class ProcessMonitor:
    """Monitorea creación de procesos en tiempo real (polling ligero)."""

    def __init__(
        self,
        store: SignatureStore,
        on_detect: Optional[Callable[[dict], None]] = None,
        interval: float = 3.0,
    ):
        self.store = store
        self.on_detect = on_detect
        self.interval = interval
        self._known_pids: set[int] = set()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # Inicializar con los PIDs actuales para no reportar los existentes
        self._seed_known_pids()

    def _seed_known_pids(self) -> None:
        try:
            for proc in psutil.process_iter(['pid']):
                self._known_pids.add(proc.info['pid'])
        except Exception:
            pass

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._poll_loop, name="killvirus-procmon", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _poll_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._scan_once()
            except Exception:
                pass
            self._stop.wait(self.interval)

    def _scan_once(self) -> None:
        current_pids: set[int] = set()
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time', 'username']):
            try:
                pid = proc.info['pid']
                current_pids.add(pid)

                if pid in self._known_pids:
                    continue

                # Proceso nuevo: verificar si su ejecutable coincide con firmas
                exe = proc.info.get('exe') or ""
                if not exe or not os.path.isfile(exe):
                    continue

                f_hash = calculate_sha256(exe)
                entry = self.store.lookup(f_hash) if f_hash else None
                if entry is not None:
                    alert = {
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "pid": pid,
                        "name": proc.info.get('name') or "",
                        "exe": exe,
                        "cmdline": " ".join(proc.info.get('cmdline') or []),
                        "malware": entry.malware_name,
                        "hash": f_hash,
                    }
                    if self.on_detect:
                        try:
                            self.on_detect(alert)
                        except Exception:
                            pass

                with self._lock:
                    self._known_pids.add(pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception:
                continue

        # Limpiar PIDs que ya no existen
        with self._lock:
            self._known_pids = {p for p in self._known_pids if p in current_pids}
