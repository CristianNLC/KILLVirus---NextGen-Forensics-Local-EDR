"""Auditoría de inicio de Windows y procesos de consola.

Sirve para responder casos como: "al prender la PC se abren pantallas de CMD
que no sé de dónde salen". Enumera las entradas de auto-inicio (Registro y
carpetas Startup) y los procesos de consola activos, y permite terminarlos.
"""

from __future__ import annotations

import os
import re
import winreg
from typing import Any

import psutil


# --- Entradas de auto-inicio -------------------------------------------------

REG_RUN_PATHS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
]

STARTUP_FOLDERS = [
    os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
    os.path.expandvars(r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup"),
]


def _extract_binary_path(cmd_string: str) -> str:
    """Extrae la ruta del ejecutable de una línea de comando del registro."""
    cmd = cmd_string.strip()
    if cmd.startswith('"'):
        match = re.match(r'^"([^"]+)"', cmd)
        return match.group(1) if match else cmd
    return cmd.split()[0] if cmd else ""


def list_startup_entries() -> list[dict[str, Any]]:
    """Devuelve todo lo que se lanza al iniciar sesión."""
    entries: list[dict[str, Any]] = []

    for root_key, subkey in REG_RUN_PATHS:
        try:
            with winreg.OpenKey(root_key, subkey, 0, winreg.KEY_READ) as key:
                count = winreg.QueryInfoKey(key)[1]
                for i in range(count):
                    try:
                        name, val, _ = winreg.EnumValue(key, i)
                    except OSError:
                        continue
                    command = str(val).strip()
                    entries.append({
                        "source": f"{subkey}",
                        "hive": "HKCU" if root_key == winreg.HKEY_CURRENT_USER else "HKLM",
                        "name": name,
                        "command": command,
                        "path": _extract_binary_path(command),
                        "exists": os.path.isfile(_extract_binary_path(command)) if _extract_binary_path(command) else False,
                    })
        except OSError:
            continue

    for folder in STARTUP_FOLDERS:
        if os.path.isdir(folder):
            for fname in os.listdir(folder):
                fpath = os.path.join(folder, fname)
                entries.append({
                    "source": "Startup folder",
                    "hive": "",
                    "name": fname,
                    "command": fpath,
                    "path": fpath,
                    "exists": os.path.isfile(fpath),
                })

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
