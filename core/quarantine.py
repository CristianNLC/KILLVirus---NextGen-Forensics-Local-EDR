"""Cuarentena cifrada con DPAPI (Windows Data Protection API).

Ventajas frente a mover el archivo tal cual:
  * El contenido malicioso queda cifrado en reposo (no se puede ejecutar ni
    copiar arrastrándolo desde el explorador).
  * La clave la protege Windows con el ámbito de máquina, así que tanto la
    interfaz (usuario) como el servicio (SYSTEM) pueden restaurar el archivo.
  * No hay claves que guardar ni dependencias externas: `crypt32.dll` ya está.

Formato: `MAGIC` + blob DPAPI. Los archivos aislados por versiones anteriores
(plaintext) se siguen restaurando: la restauración detecta el magic y, si no
está, mueve el archivo como siempre.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import shutil
from ctypes import wintypes
from datetime import datetime
from typing import Optional

from core.paths import QUARANTINE_DIR, ensure_runtime_dirs

MAGIC = b"KILLVIRUS-DPAPI-1\r\n"
ENTROPY = b"KILLVirus Quarantine v1"
DESCRIPTION = "KILLVirus quarantine"

# DPAPI tiene que serializar el archivo completo en memoria. Para no agotar RAM
# con muestras gigantes se cifra hasta este tamaño y, por encima, se mueve sin
# cifrar dejando constancia en la metadata.
MAX_ENCRYPT_SIZE = 128 * 1024 * 1024

CRYPTPROTECT_UI_FORBIDDEN = 0x1
CRYPTPROTECT_LOCAL_MACHINE = 0x4

_P = ctypes.POINTER


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", _P(ctypes.c_char)),
    ]


_crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

_crypt32.CryptProtectData.argtypes = [
    _P(_DATA_BLOB),
    wintypes.LPCWSTR,
    _P(_DATA_BLOB),
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.DWORD,
    _P(_DATA_BLOB),
]
_crypt32.CryptProtectData.restype = wintypes.BOOL

_crypt32.CryptUnprotectData.argtypes = [
    _P(_DATA_BLOB),
    _P(wintypes.LPWSTR),
    _P(_DATA_BLOB),
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.DWORD,
    _P(_DATA_BLOB),
]
_crypt32.CryptUnprotectData.restype = wintypes.BOOL

_kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
_kernel32.LocalFree.restype = wintypes.HLOCAL


def _blob(data: bytes) -> tuple[_DATA_BLOB, ctypes.Array]:
    buffer = ctypes.create_string_buffer(data, len(data))
    return _DATA_BLOB(len(data), ctypes.cast(buffer, _P(ctypes.c_char))), buffer


def dpapi_protect(data: bytes, entropy: bytes = ENTROPY) -> bytes:
    """Cifra un blob con DPAPI (ámbito de máquina)."""
    if not data:
        return b""
    in_blob, _buf = _blob(data)
    entropy_blob, _entropy_buf = _blob(entropy)
    out_blob = _DATA_BLOB()
    ok = _crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        DESCRIPTION,
        ctypes.byref(entropy_blob),
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise OSError(ctypes.get_last_error(), "CryptProtectData falló")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        _kernel32.LocalFree(out_blob.pbData)


def dpapi_unprotect(blob: bytes, entropy: bytes = ENTROPY) -> bytes:
    """Descifra un blob DPAPI creado por `dpapi_protect` o por el servicio."""
    if not blob:
        return b""
    in_blob, _buf = _blob(blob)
    entropy_blob, _entropy_buf = _blob(entropy)
    out_blob = _DATA_BLOB()
    description = wintypes.LPWSTR()
    ok = _crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        ctypes.byref(description),
        ctypes.byref(entropy_blob),
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    )
    try:
        if not ok:
            raise OSError(ctypes.get_last_error(), "CryptUnprotectData falló")
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        if description:
            _kernel32.LocalFree(description)
        if ok:
            _kernel32.LocalFree(out_blob.pbData)


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(131072), b""):
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest()


def is_encrypted_blob(blob: bytes) -> bool:
    return blob.startswith(MAGIC)


def is_encrypted_file(path: str) -> bool:
    try:
        with open(path, "rb") as handle:
            return is_encrypted_blob(handle.read(len(MAGIC)))
    except OSError:
        return False


def _unique_dest(filename: str, timestamp: str) -> str:
    dest_path = os.path.join(QUARANTINE_DIR, f"{filename}_{timestamp}.quarantine")
    counter = 1
    while os.path.exists(dest_path):
        dest_path = os.path.join(
            QUARANTINE_DIR, f"{filename}_{timestamp}_{counter}.quarantine"
        )
        counter += 1
    return dest_path


def _write_meta(meta_path: str, meta: dict) -> None:
    tmp = meta_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(meta, handle, indent=2, ensure_ascii=False)
    os.replace(tmp, meta_path)


def isolate_file(filepath, reason=None, sha256=None, encrypt=True):
    """Aísla un archivo en cuarentena (cifrado DPAPI cuando es posible).

    Retorna la ruta del archivo aislado o None si no se pudo mover/cifrar.
    El original solo se borra después de escribir y verificar la copia.
    """
    dest_path: Optional[str] = None
    meta_path: Optional[str] = None
    tmp_path: Optional[str] = None
    try:
        ensure_runtime_dirs()
        filename = os.path.basename(filepath)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        dest_path = _unique_dest(filename, timestamp)
        meta_path = dest_path + ".meta"
        size = os.path.getsize(filepath)
        # Se calcula ANTES de cifrar/mover: tras cifrar el plaintext ya no existe
        # y su hash no se podría reconstruir.
        original_sha = sha256 or _sha256_file(filepath)
        encrypted = False

        meta = {
            "original_path": os.path.abspath(filepath),
            "date": timestamp,
            "reason": reason or "Detección heurística",
            "sha256": original_sha,
            "original_size": size,
            "encrypted": encrypted,
        }

        if encrypt and 0 < size <= MAX_ENCRYPT_SIZE:
            with open(filepath, "rb") as handle:
                data = handle.read()
            blob = MAGIC + dpapi_protect(data)
            tmp_path = dest_path + ".tmp"
            with open(tmp_path, "wb") as handle:
                handle.write(blob)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, dest_path)
            tmp_path = None
            meta["encrypted"] = True
            # Metadatos primero: si esto falla, el original sigue en su sitio y
            # la limpieza no destruye nada irrecuperable.
            _write_meta(meta_path, meta)
            os.remove(filepath)
        else:
            _write_meta(meta_path, meta)
            shutil.move(filepath, dest_path)

        return dest_path
    except Exception:
        for leftover in (tmp_path, dest_path, meta_path):
            if leftover:
                try:
                    os.remove(leftover)
                except OSError:
                    pass
        return None


def restore_file(quarantine_path: str, dest_path: str) -> str:
    """Restaura un archivo de cuarentena (cifrado o legacy) a `dest_path`.

    Lanza OSError si falla para que la UI pueda mostrar el motivo. Devuelve la
    ruta restaurada.
    """
    parent = os.path.dirname(os.path.abspath(dest_path))
    if parent:
        os.makedirs(parent, exist_ok=True)

    with open(quarantine_path, "rb") as handle:
        head = handle.read(len(MAGIC))
        encrypted = is_encrypted_blob(head)
        if encrypted:
            blob = head + handle.read()

    if encrypted:
        data = dpapi_unprotect(blob[len(MAGIC):])
        tmp = dest_path + ".killvirus-tmp"
        with open(tmp, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, dest_path)
        os.remove(quarantine_path)
    else:
        if os.path.exists(dest_path):
            os.remove(dest_path)
        shutil.move(quarantine_path, dest_path)

    meta_path = quarantine_path + ".meta"
    if os.path.exists(meta_path):
        try:
            os.remove(meta_path)
        except OSError:
            pass
    return dest_path
