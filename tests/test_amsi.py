"""Tests para core/amsi.py"""

from core.amsi import AMSI


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
