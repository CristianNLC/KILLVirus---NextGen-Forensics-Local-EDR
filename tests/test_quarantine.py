"""Tests para core/quarantine.py (cifrado DPAPI y compatibilidad legacy)."""

import json
import os
import tempfile

import pytest


from core.quarantine import (
    MAGIC,
    isolate_file,
    is_encrypted_file,
    restore_file,
)


@pytest.fixture
def quarantined(tmp_path, monkeypatch):
    import core.quarantine as qmod

    monkeypatch.setattr(qmod, "QUARANTINE_DIR", str(tmp_path))
    return tmp_path


def test_isolate_file_moves_and_writes_meta(quarantined):
    victim = tempfile.mktemp(suffix=".exe")
    with open(victim, "wb") as f:
        f.write(b"MZ benigno")

    qp = isolate_file(victim, reason="Test motivo", sha256="f" * 64)
    assert qp is not None
    assert os.path.isfile(qp)
    assert not os.path.exists(victim)  # original movido

    meta_path = qp + ".meta"
    assert os.path.isfile(meta_path)
    with open(meta_path, encoding="utf-8") as f:
        meta = json.load(f)
    assert meta["reason"] == "Test motivo"
    assert meta["sha256"] == "f" * 64
    assert meta["original_path"] == os.path.abspath(victim)


def test_isolate_file_collision_safe(quarantined):
    victim1 = tempfile.mktemp(suffix=".exe")
    victim2 = tempfile.mktemp(suffix=".exe")
    with open(victim1, "wb") as f:
        f.write(b"one")
    with open(victim2, "wb") as f:
        f.write(b"two")

    qp1 = isolate_file(victim1, reason="uno")
    qp2 = isolate_file(victim2, reason="dos")
    assert qp1 != qp2
    assert os.path.isfile(qp1)
    assert os.path.isfile(qp2)


def test_isolate_file_encrypts_content(quarantined):
    payload = b"MZ malware de prueba\x00" * 64
    victim = quarantined / "muestra.exe"
    victim.write_bytes(payload)

    qp = isolate_file(str(victim), reason="Firma de prueba")
    assert qp is not None
    assert not victim.exists()

    with open(qp, "rb") as f:
        blob = f.read()
    assert blob.startswith(MAGIC)
    assert payload not in blob  # el contenido no queda en claro
    assert is_encrypted_file(qp)

    with open(qp + ".meta", encoding="utf-8") as f:
        meta = json.load(f)
    assert meta["encrypted"] is True
    assert meta["original_size"] == len(payload)
    # Hash calculado antes de cifrar: debe coincidir con el plaintext original.
    import hashlib

    assert meta["sha256"] == hashlib.sha256(payload).hexdigest()


def test_restore_encrypted_returns_original_bytes(quarantined):
    payload = b"PK\x03\x04 contenido importante" * 100
    victim = quarantined / "documento.docx"
    victim.write_bytes(payload)

    qp = isolate_file(str(victim), reason="Prueba de restauración")
    dest = quarantined / "restaurado.docx"

    restored = restore_file(qp, str(dest))
    assert restored == str(dest)
    assert dest.read_bytes() == payload
    assert not os.path.exists(qp)
    assert not os.path.exists(qp + ".meta")


def test_restore_legacy_plaintext_file(quarantined):
    """Archivos aislados con versiones anteriores no llevan MAGIC."""
    legacy = quarantined / "viejo.exe_20260101_000000.quarantine"
    legacy.write_bytes(b"MZ legacy")
    (quarantined / (legacy.name + ".meta")).write_text(
        json.dumps({"original_path": "C:\\\\x\\\\viejo.exe", "date": "20260101_000000"}),
        encoding="utf-8",
    )

    dest = quarantined / "viejo.exe"
    restore_file(str(legacy), str(dest))
    assert dest.read_bytes() == b"MZ legacy"
    assert not legacy.exists()
    assert not (quarantined / (legacy.name + ".meta")).exists()


def test_isolate_without_encryption_keeps_plaintext(quarantined):
    victim = quarantined / "plano.txt"
    victim.write_bytes(b"texto plano")

    qp = isolate_file(str(victim), reason="Sin cifrar", encrypt=False)
    assert qp is not None
    with open(qp, "rb") as f:
        assert f.read() == b"texto plano"
    with open(qp + ".meta", encoding="utf-8") as f:
        assert json.load(f)["encrypted"] is False


def test_isolate_failure_keeps_original(quarantined, monkeypatch):
    import core.quarantine as qmod

    victim = quarantined / "importante.exe"
    victim.write_bytes(b"MZ no perder")

    def fail_meta(*_args, **_kwargs):
        raise OSError("disco lleno")

    monkeypatch.setattr(qmod, "_write_meta", fail_meta)
    assert isolate_file(str(victim), reason="fallo simulado") is None
    assert victim.read_bytes() == b"MZ no perder"
    leftovers = [p for p in quarantined.iterdir() if p.name != victim.name]
    assert leftovers == []
