"""Punto de entrada de KILLVirus (aplicación de escritorio)."""

import atexit
import ctypes
import os
import sys

# Asegurar que la raíz del proyecto esté en el path de importación cuando se
# ejecuta desde el repositorio (en el .exe empaquetado no hace falta).
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core import __app_name__
from core.logging_setup import install_excepthook, setup_logging
from core.single_instance import SingleInstance

MB_ICONINFORMATION = 0x00000040


def _set_app_user_model_id():
    """Ancla el icono correcto en la barra de tareas de Windows."""
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
            "killsystem.killvirus.edr.2"
        )
    except Exception:
        pass


def _warn_already_running():
    try:
        ctypes.windll.user32.MessageBoxW(
            None,
            f"{__app_name__} ya está en ejecución.\n\n"
            "Buscá el ícono en la bandeja del sistema.",
            __app_name__,
            MB_ICONINFORMATION,
        )
    except Exception:
        pass


def main():
    _set_app_user_model_id()
    setup_logging()
    install_excepthook()

    guard = SingleInstance()
    if guard.already_running:
        _warn_already_running()
        return 0
    atexit.register(guard.close)

    # Import tardío: si ya hay una instancia no hace falta cargar Tk.
    from ui.main_window import MainWindow

    app = MainWindow()
    app.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
