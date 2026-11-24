"""Autoprotección local: ACLs de datos sensibles e integridad de archivos.

Qué protege y qué no (importante ser honesto):

  * Las ACLs impiden que **otros usuarios** (incluidos procesos comprometidos
    que corren con otra cuenta) lean, borren o sustituyan firmas, cuarentena y
    reportes. No detienen a un malware que ya corre con la misma cuenta que la
    app; para eso están el servicio, el watchdog y los canarios.
  * El manifiesto de integridad detecta modificaciones de los archivos críticos
    (código y ejecutable). Se guarda con los hashes; un atacante con la misma
    cuenta puede reescribirlo, pero entonces ya controla el equipo.

Se usan SIDs (`*S-1-5-18`, `*S-1-5-32-544`) en vez de nombres para que
funcione igual en Windows en español, inglés o cualquier idioma.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from typing import Iterable, Optional

from core.paths import (
    BASE_DIR,
    DATA_DIR,
    INTEGRITY_FILE,
    LOG_DIR,
    QUARANTINE_DIR,
    REPORTS_DIR,
)

_CREATE_NO_WINDOW = 0x08000000
_ICACLS_TIMEOUT = 60

SID_SYSTEM = "*S-1-5-18"
SID_ADMINISTRATORS = "*S-1-5-32-544"


def _hidden_flags() -> int:
    return _CREATE_NO_WINDOW if os.name == "nt" else 0


def _decode(raw: bytes) -> str:
    for encoding in ("oem", "mbcs", "utf-8"):
        try:
            return raw.decode(encoding, errors="replace")
        except LookupError:
            continue
    return str(raw)


def is_admin() -> bool:
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def current_sid() -> str:
    """SID del usuario actual (whoami /user). Fallback: nombre de usuario."""
    try:
        result = subprocess.run(
            ["whoami", "/user", "/fo", "csv", "/nh"],
            capture_output=True,
            creationflags=_hidden_flags(),
            timeout=15,
        )
        text = _decode((result.stdout or b"") + (result.stderr or b"")).strip()
        # "EQUIPO\\usuario","S-1-5-21-..."
        if result.returncode == 0 and "," in text:
            sid = text.split(",")[-1].strip().strip('"')
            if sid.upper().startswith("S-1-"):
                return "*" + sid
    except Exception:
        pass
    domain = os.environ.get("USERDOMAIN", "")
    user = os.environ.get("USERNAME", "")
    return f"{domain}\\{user}" if domain and user else user


# ------------------------------------------------------------------------ ACLs
def default_protected_dirs() -> list[str]:
    return [DATA_DIR, QUARANTINE_DIR, REPORTS_DIR, LOG_DIR]


def build_icacls_command(path: str, user: Optional[str] = None) -> list[str]:
    """Comando icacls idempotente: sin herencia y solo 3 principales."""
    principal = user or current_sid()
    return [
        "icacls",
        path,
        "/inheritance:r",
        "/grant:r",
        f"{principal}:(OI)(CI)F",
        f"{SID_SYSTEM}:(OI)(CI)F",
        f"{SID_ADMINISTRATORS}:(OI)(CI)F",
        "/T",
        "/C",
        "/Q",
    ]


def harden_path(path: str, user: Optional[str] = None) -> dict:
    """Aplica la ACL endurecida a una carpeta. Nunca lanza excepción."""
    if not os.path.isdir(path):
        return {"path": path, "ok": False, "output": "no existe"}
    try:
        result = subprocess.run(
            build_icacls_command(path, user),
            capture_output=True,
            creationflags=_hidden_flags(),
            timeout=_ICACLS_TIMEOUT,
        )
        output = _decode((result.stdout or b"") + (result.stderr or b"")).strip()
        return {"path": path, "ok": result.returncode == 0, "output": output}
    except Exception as exc:
        return {"path": path, "ok": False, "output": str(exc)}


def _dacl_protected(path: str) -> Optional[bool]:
    """True si la DACL no hereda permisos (bit SE_DACL_PROTECTED).

    Es el dato exacto que escribe `icacls /inheritance:r`, independiente del
    idioma de Windows y de los nombres de los grupos.
    """
    try:
        import ctypes
        from ctypes import wintypes

        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        advapi32.GetNamedSecurityInfoW.argtypes = [
            wintypes.LPWSTR,
            ctypes.c_int,
            wintypes.DWORD,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
        ]
        advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
        advapi32.GetSecurityDescriptorControl.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.WORD),
            ctypes.POINTER(wintypes.DWORD),
        ]
        advapi32.GetSecurityDescriptorControl.restype = wintypes.BOOL
        kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
        kernel32.LocalFree.restype = wintypes.HLOCAL

        SE_FILE_OBJECT = 1
        DACL_SECURITY_INFORMATION = 0x00000004
        SE_DACL_PROTECTED = 0x1000

        descriptor = ctypes.c_void_p()
        rc = advapi32.GetNamedSecurityInfoW(
            path,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            ctypes.byref(descriptor),
        )
        if rc != 0 or not descriptor:
            return None
        try:
            control = wintypes.WORD()
            revision = wintypes.DWORD()
            if not advapi32.GetSecurityDescriptorControl(
                descriptor, ctypes.byref(control), ctypes.byref(revision)
            ):
                return None
            return bool(control.value & SE_DACL_PROTECTED)
        finally:
            kernel32.LocalFree(descriptor)
    except Exception:
        return None


def acl_is_hardened(path: str) -> bool:
    """True si la carpeta tiene la herencia de permisos desactivada."""
    if not os.path.isdir(path):
        return False
    exact = _dacl_protected(path)
    if exact is not None:
        return exact
    # Respaldo: heurística por texto de icacls (sin entradas heredadas `(I)`).
    try:
        result = subprocess.run(
            ["icacls", path],
            capture_output=True,
            creationflags=_hidden_flags(),
            timeout=20,
        )
        text = _decode((result.stdout or b"") + (result.stderr or b""))
        return result.returncode == 0 and "(I)" not in text.upper()
    except Exception:
        return False


def harden_runtime_dirs(dirs: Optional[Iterable[str]] = None) -> dict:
    """Endurece las carpetas de datos. Devuelve un reporte serializable."""
    targets = list(dirs) if dirs is not None else default_protected_dirs()
    results = [harden_path(path) for path in targets]
    return {
        "admin": is_admin(),
        "results": results,
        "ok": all(item["ok"] for item in results) if results else False,
    }


def protection_status(dirs: Optional[Iterable[str]] = None) -> dict:
    """Resumen para la UI: admin, ACL por carpeta y estado global."""
    targets = list(dirs) if dirs is not None else default_protected_dirs()
    per_dir = {path: acl_is_hardened(path) for path in targets}
    return {
        "admin": is_admin(),
        "dirs": per_dir,
        "hardened": all(per_dir.values()) if per_dir else False,
    }


# ----------------------------------------------------------------- integridad
def critical_files(base_dir: Optional[str] = None) -> list[str]:
    """Archivos cuyo cambio debe alertar (código propio, no dependencias)."""
    base = os.path.abspath(base_dir or BASE_DIR)
    files: list[str] = []
    for name in ("app.pyw", "app.py"):
        candidate = os.path.join(base, name)
        if os.path.isfile(candidate):
            files.append(candidate)
    for folder in ("core", "ui", "services"):
        root_dir = os.path.join(base, folder)
        for root, dirnames, filenames in os.walk(root_dir):
            dirnames[:] = [d for d in dirnames if d != "__pycache__"]
            for filename in filenames:
                if filename.endswith(".py"):
                    files.append(os.path.join(root, filename))
    if getattr(sys, "frozen", False):
        files.append(os.path.abspath(sys.executable))
    return sorted(set(files))


def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(131072), b""):
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest()


def compute_manifest(base_dir: Optional[str] = None) -> dict:
    """Hashes de los archivos críticos, relativos a la raíz de la app."""
    base = os.path.abspath(base_dir or BASE_DIR)
    manifest: dict[str, str] = {}
    for path in critical_files(base):
        try:
            rel = os.path.relpath(path, base)
        except ValueError:
            rel = path
        manifest[rel] = _sha256(path)
    return {
        "app": "KILLVirus",
        "algorithm": "sha256",
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "base_dir": base,
        "files": manifest,
    }


def write_manifest(
    path: Optional[str] = None,
    base_dir: Optional[str] = None,
) -> dict:
    """Genera y guarda el manifiesto de integridad."""
    target = path or INTEGRITY_FILE
    manifest = compute_manifest(base_dir)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    tmp = target + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, ensure_ascii=False)
    os.replace(tmp, target)
    return manifest


def verify_manifest(
    path: Optional[str] = None,
    base_dir: Optional[str] = None,
) -> list[str]:
    """Compara el manifiesto con el disco. Lista de problemas legibles."""
    target = path or INTEGRITY_FILE
    try:
        with open(target, "r", encoding="utf-8") as handle:
            manifest = json.load(handle)
    except Exception:
        return ["No existe manifiesto de integridad"]

    base = os.path.abspath(base_dir or BASE_DIR)
    stored = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(stored, dict):
        return ["Manifiesto inválido"]

    problems: list[str] = []
    for rel, expected in stored.items():
        absolute = rel if os.path.isabs(rel) else os.path.join(base, rel)
        if not os.path.isfile(absolute):
            problems.append(f"desaparecido: {rel}")
            continue
        current = _sha256(absolute)
        if current and expected and current != expected:
            problems.append(f"modificado: {rel}")
    return problems
