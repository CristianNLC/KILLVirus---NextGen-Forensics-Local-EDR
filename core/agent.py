"""Agente de protección headless (sin interfaz gráfica).

Es el mismo motor que usa la ventana, pero sin Tk: lo arranca el servicio de
Windows (o `app.pyw --agent`) y deja un heartbeat en `data/agent_status.json`
para que la interfaz muestre si está vivo.

Componentes:
  * protección en vivo (watchdog) sobre las carpetas del usuario;
  * canarios antiransomware;
  * monitor de creación de procesos (firmas SHA-256 del ejecutable);
  * watchdog interno que reinicia cualquier componente caído.

La cuarentena y el registro se hacen fuera del hilo del watcher (cola propia)
para no perder eventos si un archivo tarda en copiarse.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from core import __version__
from core.canary import CanaryAlert, CanaryManager
from core.monitor.watcher import LiveProtectionManager
from core.paths import (
    AGENT_STATUS_FILE,
    INTEGRITY_FILE,
    SIGNATURES_DB,
    SIGNATURES_FILE,
    is_inside_runtime_dir,
)
from core.process_monitor import ProcessMonitor
from core.quarantine import isolate_file
from core.signatures import SignatureStore, create_signature_store

logger = logging.getLogger(__name__)

DEFAULT_WATCH_SUBDIRS = ("Downloads", "Desktop", "Documents", "Pictures")


def _existing_dirs(candidates) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for path in candidates:
        if not path:
            continue
        try:
            absolute = os.path.abspath(path)
        except Exception:
            continue
        key = os.path.normcase(absolute)
        if key in seen or not os.path.isdir(absolute):
            continue
        seen.add(key)
        out.append(absolute)
    return out


def _effective_profile() -> str:
    """Perfil del usuario real, incluso cuando el agente corre como SYSTEM.

    El servicio se instala con `--data-dir %LOCALAPPDATA%\\KILLVirus`, así que
    la ruta de datos delata el perfil del usuario que lo instaló:
    `C:\\Users\\Ana\\AppData\\Local\\KILLVirus` -> `C:\\Users\\Ana`.
    En desarrollo (datos en el repo) se usa USERPROFILE normalmente.
    """
    profile = os.environ.get("USERPROFILE", "")
    override = os.environ.get("KILLVIRUS_DATA_DIR", "").strip()
    if override:
        # La carpeta de datos siempre la pasa el instalador/UI y refleja al
        # usuario real: <perfil>\AppData\Local\KILLVirus. Funciona igual si el
        # proceso corre como SYSTEM (perfil de SYSTEM) o si el SCM heredó un
        # USERPROFILE distinto.
        parts = os.path.abspath(override).split(os.sep)
        # Estructura esperada: <perfil>\AppData\(Local|Roaming)\KILLVirus.
        # Exigir exactamente dos componentes después de "AppData" evita
        # confundir el AppData real cuando la carpeta temporal del test vive
        # dentro de él.
        for index in range(len(parts) - 1, 0, -1):
            if (
                parts[index].lower() == "appdata"
                and index + 2 == len(parts) - 1
                and parts[index + 1].lower() in ("local", "roaming")
            ):
                return os.sep.join(parts[:index])
    return profile


def default_watch_folders() -> list[str]:
    """Carpetas del usuario donde suele caer el malware descargado."""
    profile = _effective_profile()
    candidates = [os.path.join(profile, sub) for sub in DEFAULT_WATCH_SUBDIRS]
    folders = _existing_dirs(candidates)
    if not folders and profile:
        folders = _existing_dirs([profile])
    return folders


def default_canary_dirs() -> list[str]:
    profile = _effective_profile()
    return _existing_dirs(
        [
            os.path.join(profile, sub)
            for sub in ("Documents", "Desktop", "Pictures")
        ]
    )


@dataclass
class AgentOptions:
    """Configuración del agente. Todo tiene un valor por defecto seguro."""

    watch_folders: list[str] = field(default_factory=default_watch_folders)
    canary_dirs: list[str] = field(default_factory=default_canary_dirs)
    enable_live_protection: bool = True
    enable_canary: bool = True
    enable_process_monitor: bool = True
    quarantine_detections: bool = True
    canary_interval: float = 2.0
    process_interval: float = 3.0
    heartbeat_interval: float = 5.0
    watchdog_interval: float = 15.0
    status_file: str = AGENT_STATUS_FILE

    @classmethod
    def from_config(cls, config: Optional[dict]) -> "AgentOptions":
        """Lee la sección opcional `agent` de config.json."""
        config = config or {}
        section = config.get("agent") if isinstance(config.get("agent"), dict) else {}
        options = cls()
        if section:
            folders = section.get("watch_folders")
            if isinstance(folders, list):
                options.watch_folders = _existing_dirs(folders)
            canary = section.get("canary_dirs")
            if isinstance(canary, list):
                options.canary_dirs = _existing_dirs(canary)
            options.enable_live_protection = bool(
                section.get("enable_live_protection", options.enable_live_protection)
            )
            options.enable_canary = bool(
                section.get("enable_canary", options.enable_canary)
            )
            options.enable_process_monitor = bool(
                section.get("enable_process_monitor", options.enable_process_monitor)
            )
            options.quarantine_detections = bool(
                section.get("quarantine_detections", options.quarantine_detections)
            )
        return options


class ProtectionAgent:
    """Arranca y supervisa los componentes de protección sin UI."""

    def __init__(
        self,
        options: Optional[AgentOptions] = None,
        store: Optional[SignatureStore] = None,
    ):
        self.options = options or AgentOptions()
        self._owns_store = store is None
        self.store = store or create_signature_store(
            SIGNATURES_DB,
            json_path=SIGNATURES_FILE,
            use_sqlite=True,
        )
        self._live_managers: list[LiveProtectionManager] = []
        self._canary: Optional[CanaryManager] = None
        self._process_monitor: Optional[ProcessMonitor] = None

        self._stop = threading.Event()
        self._lock = threading.RLock()
        self._detect_queue: queue.Queue = queue.Queue()
        self._threads: list[threading.Thread] = []
        self._started_at: Optional[float] = None
        self._starts: dict[str, int] = {}
        self._errors: list[str] = []
        self._stats = {
            "detections": 0,
            "quarantined": 0,
            "canary_alerts": 0,
            "process_alerts": 0,
        }
        self._running = False

    # ---------------------------------------------------------------- lifecycle
    def start(self) -> None:
        """Arranca todos los componentes. Idempotente."""
        with self._lock:
            if self._running:
                return
            self._running = True
            self._started_at = time.time()
            self._stop.clear()

        self._start_live_protection()
        self._start_canary()
        self._start_process_monitor()

        for name, target in (
            ("killvirus-agent-quarantine", self._detect_worker),
            ("killvirus-agent-watchdog", self._watchdog_loop),
            ("killvirus-agent-heartbeat", self._heartbeat_loop),
        ):
            thread = threading.Thread(target=target, name=name, daemon=True)
            thread.start()
            self._threads.append(thread)

        self.write_status()
        logger.info(
            "Agente KILLVirus v%s iniciado (firmas=%s, carpetas=%s)",
            __version__,
            len(self.store),
            len(self.options.watch_folders),
        )

    def stop(self) -> None:
        """Detiene todo de forma ordenada y deja el estado final escrito."""
        with self._lock:
            if not self._running:
                return
            self._running = False
        self._stop.set()

        for manager in self._live_managers:
            try:
                manager.stop()
            except Exception:
                logger.exception("Error deteniendo protección en vivo")
        self._live_managers.clear()

        if self._canary:
            try:
                self._canary.stop_monitoring()
            except Exception:
                logger.exception("Error deteniendo canarios")
        if self._process_monitor:
            try:
                self._process_monitor.stop()
            except Exception:
                logger.exception("Error deteniendo monitor de procesos")

        # Vaciar la cola de cuarentena pendiente.
        self._detect_queue.put(None)

        for thread in self._threads:
            thread.join(timeout=5)
        self._threads.clear()

        self.write_status()
        if self._owns_store:
            try:
                self.store.close()  # type: ignore[attr-defined]
            except Exception:
                pass
        logger.info("Agente KILLVirus detenido")

    @property
    def is_running(self) -> bool:
        return self._running

    # ---------------------------------------------------------------- componente
    def _start_live_protection(self) -> None:
        if not self.options.enable_live_protection:
            return
        if not self.options.watch_folders:
            logger.warning("Agente: no hay carpetas válidas para protección en vivo")
            return
        for folder in self.options.watch_folders:
            manager = LiveProtectionManager(self.store, self._on_detect)
            try:
                manager.start(folder)
                self._live_managers.append(manager)
                self._starts["live_protection"] = self._starts.get("live_protection", 0) + 1
            except Exception as exc:
                self._errors.append(f"watcher {folder}: {exc}")
                logger.exception("No se pudo vigilar %s", folder)

    def _start_canary(self) -> None:
        if not self.options.enable_canary or not self.options.canary_dirs:
            return
        try:
            self._canary = CanaryManager(
                watch_dirs=list(self.options.canary_dirs),
                on_alert=self._on_canary_alert,
            )
            self._canary.install()
            self._canary.start_monitoring(interval=self.options.canary_interval)
            self._starts["canary"] = self._starts.get("canary", 0) + 1
        except Exception as exc:
            self._errors.append(f"canary: {exc}")
            logger.exception("No se pudieron iniciar los canarios")

    def _start_process_monitor(self) -> None:
        if not self.options.enable_process_monitor:
            return
        try:
            self._process_monitor = ProcessMonitor(
                self.store,
                on_detect=self._on_process_alert,
                interval=self.options.process_interval,
            )
            self._process_monitor.start()
            self._starts["process_monitor"] = self._starts.get("process_monitor", 0) + 1
        except Exception as exc:
            self._errors.append(f"process_monitor: {exc}")
            logger.exception("No se pudo iniciar el monitor de procesos")

    # ------------------------------------------------------------------- eventos
    def _on_detect(self, filepath: str, detection) -> None:
        """Callback del watcher: encola para no bloquear el hilo de eventos."""
        self._detect_queue.put((filepath, detection))

    def _detect_worker(self) -> None:
        while not self._stop.is_set():
            item = self._detect_queue.get()
            if item is None:
                break
            filepath, detection = item
            try:
                self._handle_detection(filepath, detection)
            except Exception:
                logger.exception("Error procesando detección de %s", filepath)

    def _handle_detection(self, filepath: str, detection) -> None:
        name = getattr(detection, "name", "Malware")
        reason = getattr(detection, "reason", "")
        logger.warning("Detección: %s (%s) en %s", name, reason, filepath)
        quarantined = False
        if self.options.quarantine_detections and os.path.isfile(filepath):
            if is_inside_runtime_dir(filepath):
                return
            qp = isolate_file(
                filepath,
                reason=f"{reason}: {name}",
                sha256=getattr(detection, "sha256", "") or "",
            )
            quarantined = qp is not None
            logger.info("Cuarentena: %s -> %s", filepath, qp)
        with self._lock:
            self._stats["detections"] += 1
            if quarantined:
                self._stats["quarantined"] += 1
        self.write_status()

    def _on_canary_alert(self, alert: CanaryAlert) -> None:
        logger.warning(
            "Canario alterado: %s (%s) proceso=%s",
            alert.canary_name,
            alert.event,
            alert.process_name or "desconocido",
        )
        with self._lock:
            self._stats["canary_alerts"] += 1
        self.write_status()

    def _on_process_alert(self, alert: dict) -> None:
        logger.warning(
            "Proceso malicioso: %s (PID %s) -> %s | %s",
            alert.get("name"),
            alert.get("pid"),
            alert.get("exe"),
            alert.get("malware"),
        )
        with self._lock:
            self._stats["process_alerts"] += 1
        self.write_status()

    # ------------------------------------------------------------------ watchdog
    def _component_status(self) -> dict[str, bool]:
        return {
            "live_protection": bool(
                self._live_managers and all(m.is_running for m in self._live_managers)
            ),
            "canary": bool(self._canary and self._canary.is_monitoring),
            "process_monitor": bool(
                self._process_monitor and self._process_monitor.is_running
            ),
        }

    def _watchdog_loop(self) -> None:
        while not self._stop.wait(self.options.watchdog_interval):
            try:
                self._watchdog_tick()
            except Exception:
                logger.exception("Error en watchdog del agente")

    def _watchdog_tick(self) -> None:
        """Reinicia componentes caídos (protección contra kills parciales)."""
        if self.options.enable_live_protection and (
            not self._live_managers
            or not all(m.is_running for m in self._live_managers)
        ):
            logger.warning("Watchdog: protección en vivo caída, reiniciando")
            for manager in self._live_managers:
                try:
                    manager.stop()
                except Exception:
                    pass
            self._live_managers.clear()
            self._start_live_protection()

        if self.options.enable_canary and not (
            self._canary and self._canary.is_monitoring
        ):
            logger.warning("Watchdog: canarios caídos, reiniciando")
            self._start_canary()

        if self.options.enable_process_monitor and not (
            self._process_monitor and self._process_monitor.is_running
        ):
            logger.warning("Watchdog: monitor de procesos caído, reiniciando")
            self._start_process_monitor()

    # ---------------------------------------------------------------- heartbeat
    def _heartbeat_loop(self) -> None:
        while not self._stop.wait(self.options.heartbeat_interval):
            try:
                self.write_status()
            except Exception:
                logger.exception("Error escribiendo heartbeat del agente")

    def status(self) -> dict:
        with self._lock:
            stats = dict(self._stats)
            errors = list(self._errors[-10:])
            started = self._started_at
        uptime = int(time.time() - started) if started else 0
        return {
            "app": "KILLVirus",
            "version": __version__,
            "pid": os.getpid(),
            "started_at": (
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(started))
                if started
                else ""
            ),
            "heartbeat": time.strftime("%Y-%m-%d %H:%M:%S"),
            "heartbeat_epoch": time.time(),
            "uptime_seconds": uptime,
            "running": self._running,
            "components": self._component_status(),
            "watch_folders": list(self.options.watch_folders),
            "signatures": len(self.store),
            "stats": stats,
            "restarts": dict(self._starts),
            "errors": errors,
        }

    def write_status(self) -> None:
        """Escribe el estado de forma atómica (la UI puede leerlo siempre)."""
        path = self.options.status_file
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as handle:
                json.dump(self.status(), handle, indent=2, ensure_ascii=False)
            os.replace(tmp, path)
        except Exception:
            logger.exception("No se pudo escribir el estado del agente")

    def verify_integrity(self) -> list[str]:
        """Verifica (si existe manifiesto) que los archivos críticos no cambiaron."""
        try:
            from core.autoprotect import verify_manifest

            if not os.path.isfile(INTEGRITY_FILE):
                return []
            problems = verify_manifest(INTEGRITY_FILE)
            for problem in problems:
                logger.warning("Integridad: %s", problem)
            if problems:
                with self._lock:
                    self._errors.append(
                        f"integridad: {len(problems)} archivo(s) alterado(s)"
                    )
            return problems
        except Exception:
            logger.exception("Error verificando integridad")
            return []


def run_agent_blocking(
    options: Optional[AgentOptions] = None,
    stop_event: Optional[threading.Event] = None,
) -> int:
    """Modo consola (`--agent`): arranca y espera hasta Ctrl+C/stop_event."""
    agent = ProtectionAgent(options)
    external_stop = stop_event or threading.Event()
    agent.start()
    agent.verify_integrity()
    try:
        while not external_stop.is_set():
            external_stop.wait(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        agent.stop()
    return 0
