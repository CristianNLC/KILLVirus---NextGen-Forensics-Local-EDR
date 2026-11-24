"""Watcher de sistema de archivos (protección en tiempo real).

Está deliberadamente desacoplado de la UI: no sabe nada de MainWindow.
Recibe un store de firmas y un callback `on_detect(filepath, detection)` que
la UI provee para decidir qué hacer con cada hallazgo (aislar, logs, etc.).
"""

from __future__ import annotations

import os
import queue
import threading
import time

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from core.paths import is_inside_runtime_dir
from core.scanner import TARGET_EXTENSIONS
from core.scan_engine import scan_file
from core.signatures import SignatureStore


class LiveProtectionHandler(FileSystemEventHandler):
    """Encola eventos del sistema de archivos y los procesa aparte.

    - No bloquea al observador con sleeps ni con hashing dentro del callback.
    - Deduplica por ruta con ventana de tiempo.
    - Escucha creación, modificación, cierre y renombrado.
    - Espera a que el archivo termine de escribirse antes de escanearlo.
    """

    def __init__(self, store: SignatureStore, on_detect, dedupe_seconds=2.0):
        super().__init__()
        self.store = store
        self.on_detect = on_detect
        self.dedupe_seconds = dedupe_seconds
        self._queue = queue.Queue()
        self._recent = {}
        self._recent_lock = threading.Lock()
        self._stop = threading.Event()
        self._worker = threading.Thread(target=self._run, name="killvirus-live", daemon=True)

    # --- ciclo de vida ---
    def start(self):
        if not self._worker.is_alive():
            self._worker.start()

    def stop(self):
        self._stop.set()
        self._queue.put(None)

    # --- callbacks de watchdog ---
    def on_created(self, event):
        self._handle(event.src_path, event.is_directory)

    def on_modified(self, event):
        self._handle(event.src_path, event.is_directory)

    def on_moved(self, event):
        self._handle(event.dest_path, event.is_directory)

    def on_closed(self, event):
        self._handle(event.src_path, event.is_directory)

    def _handle(self, filepath, is_directory):
        if is_directory or not filepath:
            return
        if os.path.splitext(filepath)[1].lower() not in TARGET_EXTENSIONS:
            return
        if self._is_duplicate(filepath):
            return
        self._queue.put(filepath)

    def _is_duplicate(self, filepath):
        now = time.monotonic()
        with self._recent_lock:
            last = self._recent.get(filepath)
            if last is not None and (now - last) < self.dedupe_seconds:
                return True
            self._recent[filepath] = now
            if len(self._recent) > 4096:
                cutoff = now - 60
                self._recent = {p: t for p, t in self._recent.items() if t >= cutoff}
        return False

    def _run(self):
        while not self._stop.is_set():
            filepath = self._queue.get()
            if filepath is None:
                break
            try:
                if is_inside_runtime_dir(filepath):
                    continue
                self._wait_until_stable(filepath)
                detection = scan_file(filepath, self.store)
                if detection is not None:
                    self.on_detect(filepath, detection)
            except Exception:
                continue

    @staticmethod
    def _wait_until_stable(filepath, attempts=6, delay=0.25):
        """Espera a que el archivo esté completo y se pueda abrir."""
        last_size = -1
        for _ in range(attempts):
            try:
                size = os.path.getsize(filepath)
                with open(filepath, "rb"):
                    pass
                if size == last_size and size >= 0:
                    return
                last_size = size
            except OSError:
                pass
            time.sleep(delay)


class LiveProtectionManager:
    """Orquesta un Observador de watchdog + un LiveProtectionHandler."""

    def __init__(self, store: SignatureStore, on_detect):
        self.store = store
        self.on_detect = on_detect
        self.observer = None
        self.handler = None

    def start(self, folder):
        if self.observer is not None:
            return
        self.handler = LiveProtectionHandler(self.store, self.on_detect)
        self.observer = Observer()
        self.observer.schedule(self.handler, folder, recursive=True)
        self.observer.start()
        self.handler.start()

    def stop(self):
        if self.handler:
            self.handler.stop()
            self.handler = None
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None

    @property
    def is_running(self):
        return self.observer is not None
