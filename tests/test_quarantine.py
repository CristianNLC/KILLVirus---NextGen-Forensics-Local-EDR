"""Tests para core/quarantine.py"""

import json
import os
import tempfile


from core.quarantine import isolate_file


def test_isolate_file_moves_and_writes_meta(tmp_path):
    # Usar una carpeta temporal como cuarentena monkeypatching QUARANTINE_DIR
    import core.quarantine as qmod

    orig = qmod.QUARANTINE_DIR
    qmod.QUARANTINE_DIR = str(tmp_path)
    try:
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
    finally:
        qmod.QUARANTINE_DIR = orig
        # limpiar
        for f in os.listdir(tmp_path):
            os.unlink(os.path.join(tmp_path, f))


def test_isolate_file_collision_safe(tmp_path):
    import core.quarantine as qmod

    orig = qmod.QUARANTINE_DIR
    qmod.QUARANTINE_DIR = str(tmp_path)
    try:
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
    finally:
        qmod.QUARANTINE_DIR = orig
        for f in os.listdir(tmp_path):
            os.unlink(os.path.join(tmp_path, f))
