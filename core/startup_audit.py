"""Auditoría de inicio de Windows y procesos de consola.

Sirve para responder casos como: "al prender la PC se abren pantallas de CMD
que no sé de dónde salen". Enumera las entradas de auto-inicio (Registro,
carpetas Startup, Servicios de Windows y Tareas Programadas) y los procesos de
consola activos, y permite terminarlos.
"""

from __future__ import annotations

import os
import re
import subprocess
import winreg
from typing import Any

import psutil


# --- Entradas de auto-inicio -------------------------------------------------

REG_RUN_PATHS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\RunOnce"),
]

STARTUP_FOLDERS = [
    os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
    os.path.expandvars(r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup"),
]

# Servicios cuyo ImagePath suele ser un ejecutable real (driver = .sys, ignorado).
SERVICES_REG_PATH = r"SYSTEM\CurrentControlSet\Services"


def _extract_binary_path(cmd_string: str) -> str:
    """Extrae la ruta del ejecutable de una línea de comando del registro."""
    cmd = cmd_string.strip()
    if cmd.startswith('"'):
        match = re.match(r'^"([^"]+)"', cmd)
        return match.group(1) if match else cmd
    return cmd.split()[0] if cmd else ""


def _normalize_path(path: str) -> str:
    """Expande variables de entorno y normaliza."""
    if not path:
        return path
    return os.path.normpath(os.path.expandvars(path))


def list_registry_run_entries() -> list[dict[str, Any]]:
    """Entradas de Run / RunOnce en el Registro."""
    entries: list[dict[str, Any]] = []

    for root_key, subkey, label in REG_RUN_PATHS:
        try:
            with winreg.OpenKey(root_key, subkey, 0, winreg.KEY_READ) as key:
                count = winreg.QueryInfoKey(key)[1]
                for i in range(count):
                    try:
                        name, val, _ = winreg.EnumValue(key, i)
                    except OSError:
                        continue
                    command = str(val).strip()
                    path = _extract_binary_path(command)
                    entries.append({
                        "source": label,
                        "hive": label.split("\\")[0],
                        "type": "Registro",
                        "name": name,
                        "command": command,
                        "path": _normalize_path(path),
                        "exists": os.path.isfile(path) if path else False,
                    })
        except OSError:
            continue

    return entries


def list_startup_folder_entries() -> list[dict[str, Any]]:
    """Archivos en las carpetas de Inicio de Windows."""
    entries: list[dict[str, Any]] = []

    for folder in STARTUP_FOLDERS:
        if os.path.isdir(folder):
            for fname in os.listdir(folder):
                fpath = os.path.join(folder, fname)
                entries.append({
                    "source": "Carpeta Inicio",
                    "hive": "",
                    "type": "Archivo",
                    "name": fname,
                    "command": fpath,
                    "path": fpath,
                    "exists": os.path.isfile(fpath),
                })

    return entries


def list_services() -> list[dict[str, Any]]:
    """Servicios de Windows (solo los que apuntan a un ejecutable, no drivers)."""
    entries: list[dict[str, Any]] = []

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, SERVICES_REG_PATH, 0, winreg.KEY_READ) as services_key:
            count = winreg.QueryInfoKey(services_key)[1]
            for i in range(count):
                try:
                    service_name = winreg.EnumKey(services_key, i)
                except OSError:
                    continue
                try:
                    with winreg.OpenKey(services_key, service_name, 0, winreg.KEY_READ) as svc_key:
                        try:
                            image_path, _ = winreg.QueryValueEx(svc_key, "ImagePath")
                        except FileNotFoundError:
                            continue
                        try:
                            display_name, _ = winreg.QueryValueEx(svc_key, "DisplayName")
                        except FileNotFoundError:
                            display_name = service_name
                        try:
                            start_type, _ = winreg.QueryValueEx(svc_key, "Start")
                        except FileNotFoundError:
                            start_type = None

                        # Start: 0=Boot, 1=System, 2=Auto, 3=Manual, 4=Disabled
                        auto_start = start_type in (0, 1, 2)

                        path = _normalize_path(_extract_binary_path(str(image_path)))
                        if not path or path.lower().endswith(".sys"):
                            continue  # Ignorar drivers de kernel

                        entries.append({
                            "source": "Servicio de Windows",
                            "hive": "HKLM",
                            "type": "Servicio",
                            "name": str(display_name),
                            "command": str(image_path),
                            "path": path,
                            "exists": os.path.isfile(path) if path else False,
                            "auto_start": auto_start,
                            "service_name": service_name,
                        })
                except OSError:
                    continue
    except OSError:
        pass

    return entries


def list_scheduled_tasks() -> list[dict[str, Any]]:
    """Tareas programadas que se ejecutan al inicio o al logon."""
    entries: list[dict[str, Any]] = []

    try:
        # schtasks devuelve CSV con encabezado; /fo CSV para parseo simple.
        result = subprocess.run(
            ["schtasks", "/query", "/fo", "CSV", "/v"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return entries

        lines = result.stdout.strip().splitlines()
        if not lines:
            return entries

        header = lines[0].split(",")
        # Índices aproximados de las columnas relevantes (pueden variar por idioma)
        idx_name = header.index("Nombre de la tarea") if "Nombre de la tarea" in header else None
        idx_cmd = None
        for h in ("Comando a ejecutar", "Command to run"):
            if h in header:
                idx_cmd = header.index(h)
                break
        idx_trigger = None
        for h in ("Activadores", "Triggers"):
            if h in header:
                idx_trigger = header.index(h)
                break

        for line in lines[1:]:
            # Parseo simple de CSV (los campos entre comillas pueden tener comas)
            parts = []
            current = ""
            in_quotes = False
            for ch in line:
                if ch == '"':
                    in_quotes = not in_quotes
                elif ch == "," and not in_quotes:
                    parts.append(current)
                    current = ""
                else:
                    current += ch
            parts.append(current)

            def get(idx):
                return parts[idx] if idx is not None and idx < len(parts) else ""

            name = get(idx_name)
            if not name:
                continue

            cmd = get(idx_cmd)
            trigger = get(idx_trigger)

            path = _normalize_path(_extract_binary_path(cmd))
            entries.append({
                "source": "Tarea Programada",
                "hive": "",
                "type": "Tarea",
                "name": name,
                "command": cmd,
                "path": path,
                "exists": os.path.isfile(path) if path else False,
                "trigger": trigger,
            })
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    return entries


def list_startup_entries() -> list[dict[str, Any]]:
    """Devuelve todo lo que se lanza al iniciar sesión (todas las fuentes)."""
    entries: list[dict[str, Any]] = []
    entries.extend(list_registry_run_entries())
    entries.extend(list_startup_folder_entries())
    entries.extend(list_services())
    entries.extend(list_scheduled_tasks())
    return entries


# --- Procesos de consola ------------------------------------------------------

CONSOLE_PROCESS_NAMES = {
    "cmd.exe", "powershell.exe", "powershell_ise.exe",
    "conhost.exe", "wt.exe", "pwsh.exe",
}


def list_console_processes() -> list[dict[str, Any]]:
    """Devuelve procesos de consola activos (CMD, PowerShell, Windows Terminal...)."""
    found: list[dict[str, Any]] = []
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time', 'username']):
        try:
            name = (proc.info.get('name') or "").lower()
            if name in CONSOLE_PROCESS_NAMES:
                found.append({
                    "pid": proc.info.get('pid'),
                    "name": proc.info.get('name'),
                    "exe": proc.info.get('exe'),
                    "cmdline": " ".join(proc.info.get('cmdline') or []),
                    "create_time": proc.info.get('create_time'),
                    "username": proc.info.get('username'),
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return found


def terminate_process(pid: int) -> bool:
    """Intenta terminar un proceso por PID. Devuelve True si tuvo éxito."""
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        proc.wait(timeout=5)
        return True
    except psutil.NoSuchProcess:
        return True  # Ya no existe
    except Exception:
        try:
            psutil.Process(pid).kill()
            return True
        except Exception:
            return False
