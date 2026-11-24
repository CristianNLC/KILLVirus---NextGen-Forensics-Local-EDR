"""Tests para core/scan_engine.py"""

import hashlib
import os
import tempfile


from core.signatures import DictStore
from core.scan_engine import Detection, scan_file, SEV_SIGNATURE


def _store_with(hash_value: str, name: str = "Test.Malware"):
    return DictStore({hash_value: {"malware_name": name}})


def test_scan_file_detects_by_hash():
    content = b"malicious content"
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(content)
        path = f.name
    try:
        h = hashlib.sha256(content).hexdigest()
        store = _store_with(h)
        det = scan_file(path, store)
        assert det is not None
        assert det.severity == SEV_SIGNATURE
        assert det.reason == "Firma SHA-256"
        assert det.name == "Test.Malware"
        assert det.sha256 == h
    finally:
        os.unlink(path)


def test_scan_file_clean_not_in_store():
    content = b"clean content"
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(content)
        path = f.name
    try:
        store = DictStore({})
        det = scan_file(path, store)
        assert det is None
    finally:
        os.unlink(path)


def test_scan_file_empty_file_not_flagged():
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bat") as f:
        pass  # vacío
        path = f.name
    try:
        store = DictStore({})
        det = scan_file(path, store)
        assert det is None
    finally:
        os.unlink(path)


def test_scan_file_nonexistent():
    assert scan_file(r"C:\no_existe\archivo.exe", DictStore({})) is None


def test_detection_dataclass_defaults():
    d = Detection(name="X", reason="Y", severity=1)
    assert d.sha256 == ""
    assert d.signed is False
    assert d.signature_message == ""
