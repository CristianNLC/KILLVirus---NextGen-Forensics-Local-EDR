"""Configuración de logging local.

Hasta ahora los errores de `core/` se tragaban con `except Exception: pass` y
la única traza visible era el cuadro de texto de la UI, que se borra en cada
escaneo. Sin eso, un fallo en un equipo de un usuario es imposible de
diagnosticar.

El log se escribe en `LOG_DIR` (en desarrollo `logs/` del repo; empaquetado
`%LOCALAPPDATA%\\KILLVirus\\logs`), rotando a 1 MB con 5 copias.
"""

import logging
import logging.handlers
import os
import sys

from core.paths import LOG_DIR, ensure_runtime_dirs

LOG_FILE_NAME = "killvirus.log"
MAX_BYTES = 1_000_000
BACKUP_COUNT = 5

_configured = False


def get_log_path():
    return os.path.join(LOG_DIR, LOG_FILE_NAME)


def setup_logging(level=logging.INFO, console=None):
    """Configura el log raíz una sola vez. Nunca lanza excepción."""
    global _configured
    root = logging.getLogger()
    if _configured:
        return root

    root.setLevel(level)
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    ensure_runtime_dirs()
    try:
        file_handler = logging.handlers.RotatingFileHandler(
            get_log_path(),
            maxBytes=MAX_BYTES,
            backupCount=BACKUP_COUNT,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)
    except OSError:
        # Sin permiso de escritura se sigue funcionando: la app no debe caerse
        # por no poder abrir el log.
        root.addHandler(logging.NullHandler())

    # En el .exe empaquetado no hay consola real; en desarrollo sí es útil.
    if console is None:
        console = not getattr(sys, "frozen", False)
    if console and sys.stderr is not None:
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        root.addHandler(stream_handler)

    _configured = True
    logging.getLogger(__name__).info(
        "Log iniciado (nivel=%s, archivo=%s)", logging.getLevelName(level), get_log_path()
    )
    return root


def install_excepthook():
    """Registra las excepciones no controladas en el log antes de cerrar."""
    previous = sys.excepthook
    logger = logging.getLogger("killvirus")

    def _hook(exc_type, exc_value, exc_tb):
        logger.critical("Excepción no controlada", exc_info=(exc_type, exc_value, exc_tb))
        if sys.stderr is not None:
            previous(exc_type, exc_value, exc_tb)

    sys.excepthook = _hook
