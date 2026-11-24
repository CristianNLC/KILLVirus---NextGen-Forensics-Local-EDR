"""Punto de entrada de KILLVirus (aplicación de escritorio y agente/servicio).

Modos:
  * sin argumentos            -> interfaz gráfica normal;
  * --agent                   -> agente headless en consola (desarrollo);
  * --service --data-dir DIR  -> host del servicio de Windows (lo lanza el SCM);
  * --install-service         -> registra el servicio (requiere admin/UAC);
  * --uninstall-service       -> elimina el servicio (requiere admin/UAC);
  * --start-service / --stop-service / --service-status;
  * --harden                  -> aplica ACLs de autoprotección + manifiesto;
  * --integrity-verify        -> comprueba el manifiesto de integridad.
"""

import atexit
import ctypes
import json
import os
import sys

# Asegurar que la raíz del proyecto esté en el path de importación cuando se
# ejecuta desde el repositorio (en el .exe empaquetado no hace falta).
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)


def _pop_option(argv, name):
    """Extrae `--name valor` o `--name=valor`. Devuelve (valor, resto)."""
    value = None
    rest = []
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg == name:
            if index + 1 < len(argv):
                value = argv[index + 1]
                index += 2
                continue
            index += 1
            continue
        if arg.startswith(name + "="):
            value = arg.split("=", 1)[1]
            index += 1
            continue
        rest.append(arg)
        index += 1
    return value, rest


# El servicio corre como SYSTEM: hay que fijar el directorio de datos ANTES de
# importar core.paths (que calcula RUNTIME_DIR en tiempo de importación).
_data_dir, _rest = _pop_option(sys.argv[1:], "--data-dir")
if _data_dir:
    os.environ["KILLVIRUS_DATA_DIR"] = os.path.abspath(_data_dir)
    sys.argv = [sys.argv[0], *_rest]

from core import __app_name__  # noqa: E402
from core.logging_setup import install_excepthook, setup_logging  # noqa: E402
from core.single_instance import SingleInstance  # noqa: E402

MB_ICONINFORMATION = 0x00000040
MB_ICONERROR = 0x00000010


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


def _load_config():
    from core.paths import CONFIG_FILE

    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


# --------------------------------------------------------------- modos headless
def _run_service_mode():
    """Ejecuta el agente como servicio de Windows (lo invoca el SCM)."""
    setup_logging()
    install_excepthook()

    from core.agent import AgentOptions, ProtectionAgent
    from core.paths import init_app
    from core.service_control import SERVICE_NAME
    from core.winservice import run_as_service

    init_app()
    agent = ProtectionAgent(AgentOptions.from_config(_load_config()))
    ok = run_as_service(SERVICE_NAME, agent.start, agent.stop)
    if not ok:
        # 1063: no lo lanzó el SCM (por ejemplo, se ejecutó a mano).
        import logging

        logging.getLogger(__name__).error(
            "El proceso no fue iniciado por el Service Control Manager. "
            "Usá --agent para el modo consola."
        )
        return 1063
    return 0


def _run_agent_mode():
    """Agente headless en consola (desarrollo o diagnóstico)."""
    import signal
    import threading

    setup_logging()
    install_excepthook()

    from core.agent import AgentOptions, run_agent_blocking
    from core.paths import init_app

    init_app()

    stop_event = threading.Event()

    def _handle(_signum, _frame):
        stop_event.set()

    for name in ("SIGINT", "SIGBREAK", "SIGTERM"):
        signal_number = getattr(signal, name, None)
        if signal_number is not None:
            try:
                signal.signal(signal_number, _handle)
            except Exception:
                pass

    return run_agent_blocking(
        AgentOptions.from_config(_load_config()), stop_event=stop_event
    )


def _cli_install_service():
    from core.service_control import install_service

    try:
        result = install_service()
    except PermissionError:
        return 5
    except Exception:
        import logging

        logging.getLogger(__name__).exception("No se pudo instalar el servicio")
        return 1
    import logging

    logging.getLogger(__name__).info(
        "Servicio instalado: %s", result["status"].get("state")
    )
    return 0 if result["status"].get("state") == "RUNNING" else 2


def _cli_uninstall_service():
    from core.service_control import uninstall_service

    try:
        result = uninstall_service()
    except PermissionError:
        return 5
    except Exception:
        import logging

        logging.getLogger(__name__).exception("No se pudo desinstalar el servicio")
        return 1
    return 0 if result.get("ok") else 1


def _cli_service_action(action):
    from core import service_control

    try:
        if action == "start":
            service_control.start_service()
        elif action == "stop":
            service_control.stop_service()
        elif action == "status":
            print(json.dumps(service_control.service_status(), indent=2))
        elif action == "harden":
            from core.autoprotect import harden_runtime_dirs, write_manifest

            harden_runtime_dirs()
            write_manifest()
        elif action == "integrity":
            from core.autoprotect import verify_manifest

            problems = verify_manifest()
            for problem in problems:
                print(problem)
            return 0 if not problems else 3
        elif action == "integrity-write":
            from core.autoprotect import write_manifest

            write_manifest()
    except PermissionError:
        return 5
    except Exception:
        import logging

        logging.getLogger(__name__).exception("Acción %s falló", action)
        return 1
    return 0


def main():
    args = sys.argv[1:]

    if "--service" in args:
        return _run_service_mode()
    if "--agent" in args:
        return _run_agent_mode()

    setup_logging()
    install_excepthook()

    if "--install-service" in args:
        return _cli_install_service()
    if "--uninstall-service" in args:
        return _cli_uninstall_service()
    for flag, action in (
        ("--start-service", "start"),
        ("--stop-service", "stop"),
        ("--service-status", "status"),
        ("--harden", "harden"),
        ("--integrity-verify", "integrity"),
        ("--integrity-write", "integrity-write"),
    ):
        if flag in args:
            return _cli_service_action(action)

    _set_app_user_model_id()

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
