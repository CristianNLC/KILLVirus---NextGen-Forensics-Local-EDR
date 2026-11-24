"""Host mínimo de servicio de Windows sin pywin32.

Implementa el contrato del Service Control Manager con `ctypes`:

  * `StartServiceCtrlDispatcherW` conecta el proceso con el SCM.
  * `RegisterServiceCtrlHandlerExW` atiende parada/apagado.
  * `SetServiceStatus` reporta START_PENDING/RUNNING/STOPPED.

Si el proceso se lanza desde una consola (no desde el SCM), la llamada
devuelve False con el error 1063 y el llamador puede caer a modo consola.
"""

from __future__ import annotations

import ctypes
import logging
import threading
from ctypes import wintypes
from typing import Callable, Optional

logger = logging.getLogger(__name__)

SERVICE_WIN32_OWN_PROCESS = 0x00000010
SERVICE_ACCEPT_STOP = 0x00000001
SERVICE_ACCEPT_SHUTDOWN = 0x00000004

SERVICE_STOPPED = 0x00000001
SERVICE_START_PENDING = 0x00000002
SERVICE_STOP_PENDING = 0x00000003
SERVICE_RUNNING = 0x00000004

SERVICE_CONTROL_STOP = 0x00000001
SERVICE_CONTROL_SHUTDOWN = 0x00000005

ERROR_FAILED_SERVICE_CONTROLLER_CONNECT = 1063

_advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)


class SERVICE_STATUS(ctypes.Structure):
    _fields_ = [
        ("dwServiceType", wintypes.DWORD),
        ("dwCurrentState", wintypes.DWORD),
        ("dwControlsAccepted", wintypes.DWORD),
        ("dwWin32ExitCode", wintypes.DWORD),
        ("dwServiceSpecificExitCode", wintypes.DWORD),
        ("dwCheckPoint", wintypes.DWORD),
        ("dwWaitHint", wintypes.DWORD),
    ]


SERVICE_MAIN_FUNCTION = ctypes.WINFUNCTYPE(
    None, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR)
)
HANDLER_EX = ctypes.WINFUNCTYPE(
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.c_void_p,
    ctypes.c_void_p,
)


class SERVICE_TABLE_ENTRY(ctypes.Structure):
    _fields_ = [
        ("lpServiceName", wintypes.LPWSTR),
        ("lpServiceProc", SERVICE_MAIN_FUNCTION),
    ]


_advapi32.StartServiceCtrlDispatcherW.argtypes = [
    ctypes.POINTER(SERVICE_TABLE_ENTRY)
]
_advapi32.StartServiceCtrlDispatcherW.restype = wintypes.BOOL

_advapi32.RegisterServiceCtrlHandlerExW.argtypes = [
    wintypes.LPCWSTR,
    HANDLER_EX,
    ctypes.c_void_p,
]
_advapi32.RegisterServiceCtrlHandlerExW.restype = wintypes.HANDLE

_advapi32.SetServiceStatus.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(SERVICE_STATUS),
]
_advapi32.SetServiceStatus.restype = wintypes.BOOL


class WindowsService:
    """Envuelve una función de arranque/parada como servicio de Windows."""

    def __init__(
        self,
        name: str,
        run_fn: Callable[[], None],
        stop_fn: Optional[Callable[[], None]] = None,
    ):
        self.name = name
        self.run_fn = run_fn
        self.stop_fn = stop_fn
        self._status_handle: Optional[int] = None
        self._stop_event = threading.Event()
        # Mantener referencias vivas: ctypes no las conserva solo.
        self._handler_cb = HANDLER_EX(self._on_control)
        self._main_cb = SERVICE_MAIN_FUNCTION(self._service_main)

    # ------------------------------------------------------------------ estado
    def _report(
        self,
        state: int,
        controls: int = 0,
        win32_exit: int = 0,
        checkpoint: int = 0,
        wait_hint: int = 0,
    ) -> None:
        if not self._status_handle:
            return
        status = SERVICE_STATUS(
            SERVICE_WIN32_OWN_PROCESS,
            state,
            controls,
            win32_exit,
            0,
            checkpoint,
            wait_hint,
        )
        _advapi32.SetServiceStatus(self._status_handle, ctypes.byref(status))

    def _on_control(self, control, _event_type, _data, _context):
        if control in (SERVICE_CONTROL_STOP, SERVICE_CONTROL_SHUTDOWN):
            logger.info("SCM solicitó detener el servicio")
            self._report(SERVICE_STOP_PENDING, wait_hint=15000)
            self._stop_event.set()
        return 0

    # ------------------------------------------------------------- entry points
    def _service_main(self, _argc, _argv) -> None:
        self._status_handle = _advapi32.RegisterServiceCtrlHandlerExW(
            self.name, self._handler_cb, None
        )
        if not self._status_handle:
            logger.error(
                "RegisterServiceCtrlHandlerExW falló (error=%s)",
                ctypes.get_last_error(),
            )
            return

        self._report(SERVICE_START_PENDING, checkpoint=1, wait_hint=15000)
        exit_code = 0
        try:
            self.run_fn()
        except Exception:
            logger.exception("Fallo arrancando el agente del servicio")
            exit_code = 1
        else:
            self._report(
                SERVICE_RUNNING,
                controls=SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
            )
            # El servicio permanece vivo hasta que el SCM pida parar.
            while not self._stop_event.wait(1.0):
                pass

        try:
            if self.stop_fn:
                self.stop_fn()
        except Exception:
            logger.exception("Fallo deteniendo el agente del servicio")
            exit_code = exit_code or 1
        finally:
            self._report(SERVICE_STOPPED, win32_exit=exit_code)
            self._status_handle = None

    def dispatch(self) -> bool:
        """Conecta con el SCM. False si no fuimos lanzados como servicio."""
        table = (SERVICE_TABLE_ENTRY * 2)()
        table[0].lpServiceName = self.name
        table[0].lpServiceProc = self._main_cb
        table[1].lpServiceName = None
        table[1].lpServiceProc = SERVICE_MAIN_FUNCTION()

        ok = _advapi32.StartServiceCtrlDispatcherW(table)
        if ok:
            return True

        error = ctypes.get_last_error()
        if error == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT:
            return False
        raise OSError(error, "StartServiceCtrlDispatcherW falló")


def run_as_service(
    name: str,
    run_fn: Callable[[], None],
    stop_fn: Optional[Callable[[], None]] = None,
) -> bool:
    """Atajo: devuelve True si el proceso corrió como servicio."""
    return WindowsService(name, run_fn, stop_fn).dispatch()
