import ctypes
from ctypes import wintypes

ERROR_ALREADY_EXISTS = 183

class SingleInstance:
    """Garantiza mediante un Mutex nativo de Windows que solo exista 1 instancia activa."""
    def __init__(self, mutex_name="AntivirusLocal_SingleInstance_Mutex"):
        self.mutex_name = mutex_name
        self.kernel32 = ctypes.windll.kernel32
        self.mutex = self.kernel32.CreateMutexW(None, wintypes.BOOL(False), self.mutex_name)
        self.last_error = self.kernel32.GetLastError()

    def is_running(self):
        return self.last_error == ERROR_ALREADY_EXISTS

    def close(self):
        if self.mutex:
            self.kernel32.CloseHandle(self.mutex)
            self.mutex = None