"""Garantiza una sola instancia activa por sesión de Windows.

Dos instancias significan dos watchers sobre la misma carpeta, dos workers
compitiendo por los mismos archivos y cuarentenas duplicadas. El mutex del
kernel es la forma más barata de evitarlo antes de abrir la ventana.
"""

import ctypes
from ctypes import wintypes

ERROR_ALREADY_EXISTS = 183

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_kernel32.CreateMutexW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
_kernel32.CreateMutexW.restype = wintypes.HANDLE
_kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
_kernel32.CloseHandle.restype = wintypes.BOOL


class SingleInstance:
    """Mutex con nombre: la segunda instancia detecta que ya existe."""

    def __init__(self, mutex_name="KILLVirus_SingleInstance_Mutex"):
        self.mutex_name = mutex_name
        self._handle = _kernel32.CreateMutexW(None, False, mutex_name)
        last_error = ctypes.get_last_error()
        if not self._handle:
            raise OSError(last_error, "No se pudo crear el mutex de instancia única")
        self.already_running = last_error == ERROR_ALREADY_EXISTS

    def is_running(self):
        """Alias histórico del atributo `already_running`."""
        return self.already_running

    def close(self):
        if self._handle:
            _kernel32.CloseHandle(self._handle)
            self._handle = None
            self.already_running = False

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()
