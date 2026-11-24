"""Tests para core/service_control.py y core/winservice.py."""

import json
import time

import core.service_control as sc


def test_build_bin_path_frozen_contains_service_flag():
    command = sc.build_bin_path(
        data_dir=r"C:\Datos KILLVirus",
        frozen=True,
        executable=r"C:\Program Files\KILLVirus\KILLVirus.exe",
    )
    assert "--service" in command
    assert "KILLVirus.exe" in command
    assert "--data-dir" in command
    assert "Datos KILLVirus" in command


def test_build_bin_path_dev_uses_app_pyw():
    command = sc.build_bin_path(
        data_dir=r"C:\proyecto",
        frozen=False,
        executable=r"C:\Python314\python.exe",
        app_path=r"C:\proyecto\app.pyw",
    )
    assert "app.pyw" in command
    assert "python.exe" in command
    assert "--service" in command


def test_service_status_of_missing_service_does_not_raise():
    status = sc.service_status("KILLVirusAgentInexistente123")
    assert status["installed"] is False
    assert status["state"] == "NOT_INSTALLED"
    assert status["pid"] is None


def test_is_admin_returns_bool():
    assert isinstance(sc.is_admin(), bool)


def test_current_user_is_not_empty():
    assert sc.current_user()


def test_read_agent_status_missing_file(tmp_path, monkeypatch):
    monkeypatch.setattr(sc, "AGENT_STATUS_FILE", str(tmp_path / "nada.json"))
    result = sc.read_agent_status()
    assert result["available"] is False
    assert result["fresh"] is False


def test_read_agent_status_fresh_and_stale(tmp_path, monkeypatch):
    status_file = tmp_path / "agent_status.json"
    monkeypatch.setattr(sc, "AGENT_STATUS_FILE", str(status_file))

    status_file.write_text(
        json.dumps({"pid": 123, "heartbeat_epoch": time.time()}), encoding="utf-8"
    )
    result = sc.read_agent_status()
    assert result["available"] is True
    assert result["fresh"] is True
    assert result["data"]["pid"] == 123

    status_file.write_text(
        json.dumps({"pid": 123, "heartbeat_epoch": time.time() - 600}), encoding="utf-8"
    )
    assert sc.read_agent_status()["fresh"] is False


def test_winservice_module_binds_windows_api():
    from core import winservice

    assert winservice.SERVICE_RUNNING == 4
    assert winservice.SERVICE_CONTROL_STOP == 1
    # No llamamos a StartServiceCtrlDispatcher aquí: solo verificamos que el
    # host se construye y mantiene vivos los callbacks.
    service = winservice.WindowsService("KILLVirusTest", lambda: None, lambda: None)
    assert service.name == "KILLVirusTest"
    assert service._main_cb is not None
    assert service._handler_cb is not None


def test_service_status_parses_localized_output(monkeypatch):
    """sc.exe en español imprime ESTADO/NOMBRE_RUTA_BINARIO, no STATE/PATH."""

    class FakeResult:
        returncode = 0
        stderr = b""

        def __init__(self, text):
            self.stdout = text.encode("oem", errors="replace")

    queryex = (
        "NOMBRE_SERVICIO: KILLVirusAgent\r\n"
        "        TIPO               : 10  WIN32_OWN_PROCESS\r\n"
        "        ESTADO             : 4  RUNNING\r\n"
        "        PID                : 4321\r\n"
    )
    qc = (
        "[SC] QueryServiceConfig CORRECTO\r\n\r\n"
        "NOMBRE_SERVICIO: KILLVirusAgent\r\n"
        "        NOMBRE_RUTA_BINARIO: C:\\Python314\\python.exe app.pyw --service\r\n"
    )

    def fake_sc(*args):
        if args and args[0] == "queryex":
            return FakeResult(queryex)
        return FakeResult(qc)

    monkeypatch.setattr(sc, "_sc", fake_sc)
    status = sc.service_status("KILLVirusAgent")
    assert status["installed"] is True
    assert status["state"] == "RUNNING"
    assert status["pid"] == 4321
    assert "python.exe" in status["bin_path"]
