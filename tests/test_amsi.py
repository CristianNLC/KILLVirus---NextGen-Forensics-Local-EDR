"""Tests para core/amsi.py"""

import ctypes

import core.amsi as amsi_module
from core.amsi import AMSI


def test_hresult_type_is_defined_for_python_313():
    # Python 3.13 no expone ctypes.wintypes.HRESULT (sí 3.14); el módulo debe
    # traer su propia definición para que el .exe compilado con 3.13 arranque.
    assert amsi_module.HRESULT is ctypes.c_long


def test_amsi_init_survives_unexpected_dll_errors(monkeypatch):
    """Un fallo raro de AMSI no debe tumbar la interfaz."""

    def fail(*_args, **_kwargs):
        raise AttributeError("simulado: HRESULT ausente")

    monkeypatch.setattr(amsi_module.ctypes, "WinDLL", fail)
    scanner = amsi_module.AMSI()
    assert scanner.available is False
    malicious, message = scanner.scan_string("contenido")
    assert malicious is False
    assert "no disponible" in message


def test_amsi_init_does_not_crash():
    amsi = AMSI()
    # No falla aunque AMSI no esté disponible
    assert isinstance(amsi.available, bool)


def test_amsi_scan_string_empty():
    amsi = AMSI()
    malicious, msg = amsi.scan_string("")
    assert malicious is False
    assert "vacío" in msg or "AMSI no disponible" in msg
    amsi.close()


def test_amsi_close_twice():
    amsi = AMSI()
    amsi.close()
    amsi.close()  # no debe lanzar excepción
