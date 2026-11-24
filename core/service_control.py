"""Instalación y control del servicio de Windows del agente.

Todo se apoya en `sc.exe` (incluido en Windows), así que no hace falta
pywin32, NSSM ni ningún instalador externo. Las operaciones que modifican el
SCM requieren elevación; la UI las lanza con UAC mediante `elevate_self()`.
"""

from __future__ import annotations

import ctypes
import getpass
import json
import os
import re
import subprocess
import sys
import time
from typing import Optional

from core.paths import AGENT_STATUS_FILE, BASE_DIR, RUNTIME_DIR

SERVICE_NAME = "KILLVirusAgent"
SERVICE_DISPLAY = "KILLVirus Protection Agent"
SERVICE_DESCRIPTION = (
    "Agente de proteccion en tiempo real de KILLVirus: watcher, canarios "
    "antiransomware y monitor de procesos. Sin telemetria ni nube."
)

_CREATE_NO_WINDOW = 0x08000000
_SC_TIMEOUT = 30

# Tokens del estado que sc.exe imprime en inglés aunque la etiqueta esté
# localizada ("ESTADO" en español, "STATE" en inglés, etc.).
_STATE_TOKENS = (
    "START_PENDING",
    "STOP_PENDING",
    "CONTINUE_PENDING",
    "PAUSE_PENDING",
    "PAUSED",
    "RUNNING",
    "STOPPED",
)


# --------------------------------------------------------------------- helpers
def is_admin() -> bool:
    """True si el proceso actual tiene privilegios de administrador."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _hidden_flags() -> int:
    return _CREATE_NO_WINDOW if os.name == "nt" else 0


def _sc(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["sc.exe", *args],
        capture_output=True,
        creationflags=_hidden_flags(),
        timeout=_SC_TIMEOUT,
    )


def _decode(result: subprocess.CompletedProcess) -> str:
    raw = (result.stdout or b"") + (result.stderr or b"")
    for encoding in ("oem", "mbcs", "utf-8"):
        try:
            return raw.decode(encoding, errors="replace").strip()
        except (LookupError, AttributeError):
            continue
    return str(raw)


def current_user() -> str:
    """Principal de Windows para reglas icacls (dominio\\usuario)."""
    domain = os.environ.get("USERDOMAIN", "")
    user = os.environ.get("USERNAME") or getpass.getuser()
    return f"{domain}\\{user}" if domain and user else user


def build_bin_path(
    data_dir: Optional[str] = None,
    frozen: Optional[bool] = None,
    executable: Optional[str] = None,
    app_path: Optional[str] = None,
) -> str:
    """Comando que el SCM ejecutará para el servicio.

    En desarrollo usa ``python.exe app.pyw --service``. Empaquetado usa el
    propio .exe. En ambos casos se pasa ``--data-dir`` para que el servicio
    (SYSTEM) comparta datos con la interfaz del usuario.
    """
    frozen = bool(getattr(sys, "frozen", False)) if frozen is None else frozen
    data_dir = data_dir or RUNTIME_DIR

    if frozen:
        exe = executable or sys.executable
        args: list[str] = []
    else:
        exe = executable or sys.executable
        if exe.lower().endswith("pythonw.exe"):
            candidate = exe[:-len("pythonw.exe")] + "python.exe"
            if os.path.isfile(candidate):
                exe = candidate
        args = [app_path or os.path.join(BASE_DIR, "app.pyw")]

    args += ["--service", "--data-dir", os.path.abspath(data_dir)]
    return subprocess.list2cmdline([exe, *args])


def service_status(name: str = SERVICE_NAME) -> dict:
    """Consulta el SCM. Nunca lanza excepción.

    `sc.exe` localiza las etiquetas pero deja el estado en inglés
    (RUNNING/STOPPED/...), así que no se busca "STATE" sino el token.
    """
    info = {
        "name": name,
        "installed": False,
        "state": "NOT_INSTALLED",
        "pid": None,
        "raw": "",
        "bin_path": "",
    }
    try:
        query = _sc("queryex", name)
        info["raw"] = _decode(query)
        if query.returncode != 0:
            return info
        info["installed"] = True

        for token in _STATE_TOKENS:
            if re.search(rf"\b{token}\b", info["raw"]):
                info["state"] = token
                break

        pid_match = re.search(r"(?im)^\s*PID\b[^:]*:\s*(\d+)", info["raw"])
        if pid_match:
            info["pid"] = int(pid_match.group(1))

        config = _sc("qc", name)
        if config.returncode == 0:
            for line in _decode(config).splitlines():
                if ":" not in line:
                    continue
                value = line.split(":", 1)[1].strip()
                lower = value.lower()
                if (
                    re.match(r'^(?:"?[A-Za-z]:\\|\\\\|")', value)
                    and (".exe" in lower or ".pyw" in lower or ".py" in lower)
                ):
                    info["bin_path"] = value
                    break
    except Exception as exc:  # sc.exe ausente o bloqueado
        info["raw"] = f"error: {exc}"
    return info


def _wait_for_state(state: str, timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if service_status().get("state") == state:
            return True
        time.sleep(0.5)
    return False


def install_service(data_dir: Optional[str] = None) -> dict:
    """Crea (o recrea) el servicio. Requiere administrador."""
    if not is_admin():
        raise PermissionError("Se requieren privilegios de administrador")

    bin_path = build_bin_path(data_dir=data_dir)
    log: list[str] = []

    existing = service_status()
    if existing["installed"]:
        _sc("stop", SERVICE_NAME)
        _wait_for_state("STOPPED", timeout=10)
        _sc("delete", SERVICE_NAME)
        time.sleep(1.5)
        log.append("servicio anterior eliminado")

    created = _sc(
        "create",
        SERVICE_NAME,
        "binPath=",
        bin_path,
        "start=",
        "auto",
        "DisplayName=",
        SERVICE_DISPLAY,
        "obj=",
        "LocalSystem",
    )
    log.append(_decode(created))
    if created.returncode != 0:
        raise OSError(f"sc create falló: {log[-1]}")

    _sc("description", SERVICE_NAME, SERVICE_DESCRIPTION)
    # Recuperación: Windows reinicia el agente si se cae.
    _sc(
        "failure",
        SERVICE_NAME,
        "reset=",
        "86400",
        "actions=",
        "restart/5000/restart/15000/restart/60000",
    )
    started = _sc("start", SERVICE_NAME)
    log.append(_decode(started))
    _wait_for_state("RUNNING", timeout=20)

    return {
        "bin_path": bin_path,
        "status": service_status(),
        "log": log,
    }


def uninstall_service() -> dict:
    """Detiene y elimina el servicio. Requiere administrador."""
    if not is_admin():
        raise PermissionError("Se requieren privilegios de administrador")

    log: list[str] = []
    stop = _sc("stop", SERVICE_NAME)
    log.append(_decode(stop))
    _wait_for_state("STOPPED", timeout=10)
    delete = _sc("delete", SERVICE_NAME)
    log.append(_decode(delete))
    return {"ok": delete.returncode == 0, "log": log, "status": service_status()}


def start_service() -> dict:
    if not is_admin():
        raise PermissionError("Se requieren privilegios de administrador")
    result = _sc("start", SERVICE_NAME)
    _wait_for_state("RUNNING", timeout=20)
    return {"ok": result.returncode == 0, "output": _decode(result), "status": service_status()}


def stop_service() -> dict:
    if not is_admin():
        raise PermissionError("Se requieren privilegios de administrador")
    result = _sc("stop", SERVICE_NAME)
    _wait_for_state("STOPPED", timeout=15)
    return {"ok": result.returncode == 0, "output": _decode(result), "status": service_status()}


# ------------------------------------------------------------------ elevación
def run_elevated(executable: str, params: list[str]) -> bool:
    """Lanza un proceso con UAC (runas). True si el usuario aceptó."""
    try:
        params_str = subprocess.list2cmdline(params)
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", executable, params_str, None, 1
        )
        return int(rc) > 32
    except Exception:
        return False


def self_command(extra_args: list[str]) -> tuple[str, list[str]]:
    """Comando para relanzar la app con argumentos (dev o empaquetada)."""
    if getattr(sys, "frozen", False):
        return sys.executable, list(extra_args)
    return sys.executable, [os.path.join(BASE_DIR, "app.pyw"), *extra_args]


def elevate_self(extra_args: list[str]) -> bool:
    """Pide UAC y ejecuta `app.pyw <args>` (install/uninstall/harden/...)."""
    executable, params = self_command(extra_args)
    return run_elevated(executable, params)


# ------------------------------------------------------------ estado del agente
def read_agent_status(max_age: float = 90.0) -> dict:
    """Lee el heartbeat del agente y marca si está fresco."""
    result: dict = {"available": False, "fresh": False, "data": {}}
    try:
        with open(AGENT_STATUS_FILE, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        result["data"] = data
        result["available"] = True
        heartbeat = float(data.get("heartbeat_epoch") or 0)
        result["fresh"] = bool(heartbeat and (time.time() - heartbeat) <= max_age)
    except Exception:
        pass
    return result
