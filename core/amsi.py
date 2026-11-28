"""Interfaz AMSI (Anti-Malware Scan Interface) de Windows.

Permite enviar contenido de scripts (PowerShell, VBScript, JScript, etc.)
al motor de antivirus instalado en el sistema (Defender, etc.) antes de que
se ejecute. Útil para detectar scripts ofuscados que pasan desapercibidos en
el análisis estático de disco.

Nota: AMSI requiere Windows 10+ y un antivirus que lo implemente (Defender lo
hace por defecto). En sistemas sin AMSI, el modulo devuelve resultados
neutros sin fallar.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes

# Python 3.13 no expone ``HRESULT`` en ``ctypes.wintypes`` (sí lo hace 3.14).
# En Win32 es un LONG de 32 bits; definirlo aquí evita que el ejecutable
# compilado con 3.13 falle al importar la interfaz.
HRESULT = ctypes.c_long

# Constantes AMSI
AMSI_RESULT_CLEAN = 0
AMSI_RESULT_NOT_DETECTED = 1
AMSI_RESULT_BLOCKED_BY_ADMIN_START = 0x3000
AMSI_RESULT_BLOCKED_BY_ADMIN_END = 0x3FFF
AMSI_RESULT_DETECTED = 0x10001

AMSI_ATTRIBUTE_NAME = 0
AMSI_ATTRIBUTE_SOURCE = 1
AMSI_ATTRIBUTE_URL = 2
AMSI_ATTRIBUTE_CONTENT = 3


class AMSI:
    """Wrapper sobre amsi.dll para escaneo de cadenas en memoria."""

    def __init__(self):
        self.available = False
        self._amsi = None
        self._session = None
        self._init()

    def _init(self) -> None:
        # AMSI es opcional: si la DLL no existe, no exporta alguna función o
        # cambia la firma, la app debe seguir funcionando sin él. Atrapar solo
        # OSError dejaba pasar AttributeError y tumbaba toda la interfaz.
        try:
            self._amsi = ctypes.WinDLL("amsi.dll")

            # AMSI_RESULT es un DWORD (32 bits sin signo)
            self._amsi.AmsiInitialize.argtypes = [
                wintypes.LPWSTR,
                ctypes.POINTER(wintypes.HANDLE),
            ]
            self._amsi.AmsiInitialize.restype = HRESULT

            self._amsi.AmsiScanString.argtypes = [
                wintypes.HANDLE,
                wintypes.LPWSTR,
                wintypes.LPWSTR,
                wintypes.LPWSTR,
                ctypes.POINTER(wintypes.DWORD),
            ]
            self._amsi.AmsiScanString.restype = HRESULT

            self._amsi.AmsiCloseSession.argtypes = [wintypes.HANDLE]
            self._amsi.AmsiCloseSession.restype = None

            session = wintypes.HANDLE()
            hr = self._amsi.AmsiInitialize("KILLVirus", ctypes.byref(session))
            if hr == 0:  # S_OK
                self._session = session
                self.available = True
        except Exception:
            self._amsi = None
            self._session = None
            self.available = False

    def scan_string(self, content: str, content_name: str = "KILLVirus Scan") -> tuple[bool, str]:
        """
        Escanea una cadena de contenido con AMSI.

        Retorna: (es_malicioso, mensaje)
        """
        if not self.available:
            return False, "AMSI no disponible en este sistema"

        if not content:
            return False, "Contenido vacío"

        result = wintypes.DWORD(0)
        hr = self._amsi.AmsiScanString(
            self._session,
            content,
            content_name,
            None,
            ctypes.byref(result),
        )

        if hr != 0:
            return False, f"Error AMSI (HRESULT: {hr:#x})"

        value = result.value
        if value == AMSI_RESULT_DETECTED:
            return True, "AMSI detectó contenido malicioso"
        if AMSI_RESULT_BLOCKED_BY_ADMIN_START <= value <= AMSI_RESULT_BLOCKED_BY_ADMIN_END:
            return True, "AMSI bloqueado por administrador"
        if value in (AMSI_RESULT_CLEAN, AMSI_RESULT_NOT_DETECTED):
            return False, "AMSI: contenido limpio"
        return False, f"AMSI: resultado desconocido ({value})"

    def close(self) -> None:
        if self._amsi and self._session:
            try:
                self._amsi.AmsiCloseSession(self._session)
            except Exception:
                pass
            self._session = None
