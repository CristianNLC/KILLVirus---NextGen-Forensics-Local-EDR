"""Tests para core/canary.py"""

import os
import tempfile

from core.canary import CanaryManager, CANARY_FILES


def test_canary_install_and_verify():
    d = tempfile.mkdtemp()
    m = CanaryManager(watch_dirs=[d])
    installed = m.install()
    assert len(installed) == len(CANARY_FILES)
    for p in installed:
        assert os.path.isfile(p)
    results = m.verify()
    assert all(results.values())
    m.stop_monitoring()


def test_canary_detects_modification():
    d = tempfile.mkdtemp()
    m = CanaryManager(watch_dirs=[d])
    m.install()
    results = m.verify()
    assert all(results.values())

    p = m.canary_paths[0]
    with open(p, "a", encoding="utf-8") as f:
        f.write("modificado")
    results2 = m.verify()
    assert not results2[p]
    m.stop_monitoring()


def test_canary_detects_deletion():
    d = tempfile.mkdtemp()
    m = CanaryManager(watch_dirs=[d])
    m.install()
    p = m.canary_paths[0]
    os.unlink(p)
    results = m.verify()
    assert not results[p]
    m.stop_monitoring()


def test_writer_attribution_prefers_open_handle(monkeypatch):
    m = CanaryManager(watch_dirs=[])
    monkeypatch.setattr(
        m,
        "_processes_with_open_file",
        lambda path: [{"name": "evil.exe", "exe": r"C:\Temp\evil.exe", "pid": 42}],
    )
    # No debería consultar los contadores si ya hay un handle abierto.
    monkeypatch.setattr(
        m, "_read_io_counters", lambda: (_ for _ in ()).throw(AssertionError())
    )
    writer = m._find_recent_writer(r"C:\Users\Ana\Documents\canary.txt")
    assert writer["pid"] == 42
    assert writer["evidence"] == "handle"


def test_writer_attribution_by_io_delta(monkeypatch):
    m = CanaryManager(watch_dirs=[])
    m._io_snapshot = {
        42: {"name": "evil.exe", "exe": r"C:\Temp\evil.exe",
             "write_bytes": 1000, "write_count": 2},
        43: {"name": "idle.exe", "exe": r"C:\Temp\idle.exe",
             "write_bytes": 500, "write_count": 5},
    }
    current = {
        42: {"name": "evil.exe", "exe": r"C:\Temp\evil.exe",
             "write_bytes": 1300, "write_count": 3},
        43: {"name": "idle.exe", "exe": r"C:\Temp\idle.exe",
             "write_bytes": 500, "write_count": 5},
    }
    monkeypatch.setattr(m, "_processes_with_open_file", lambda path: [])
    writer = m._find_recent_writer("canary.txt", current)
    assert writer["pid"] == 42
    assert writer["evidence"] == "io"


def test_writer_attribution_is_conservative_when_ambiguous(monkeypatch):
    m = CanaryManager(watch_dirs=[])
    m._io_snapshot = {
        42: {"name": "a.exe", "exe": r"C:\Temp\a.exe", "write_bytes": 0, "write_count": 0},
        43: {"name": "b.exe", "exe": r"C:\Temp\b.exe", "write_bytes": 0, "write_count": 0},
    }
    current = {
        42: {"name": "a.exe", "exe": r"C:\Temp\a.exe", "write_bytes": 300, "write_count": 1},
        43: {"name": "b.exe", "exe": r"C:\Temp\b.exe", "write_bytes": 200, "write_count": 2},
    }
    monkeypatch.setattr(m, "_processes_with_open_file", lambda path: [])
    assert m._find_recent_writer("canary.txt", current) is None


def test_writer_attribution_ignores_system_binaries(monkeypatch):
    m = CanaryManager(watch_dirs=[])
    system_exe = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "svchost.exe")
    m._io_snapshot = {
        7: {"name": "svchost.exe", "exe": system_exe, "write_bytes": 0, "write_count": 0},
    }
    current = {
        7: {"name": "svchost.exe", "exe": system_exe, "write_bytes": 900, "write_count": 4},
    }
    monkeypatch.setattr(m, "_processes_with_open_file", lambda path: [])
    assert m._find_recent_writer("canary.txt", current) is None


def test_scan_once_records_writer_evidence(monkeypatch):
    d = tempfile.mkdtemp()
    m = CanaryManager(watch_dirs=[d])
    alerts = []
    m.on_alert = alerts.append
    m.install()
    p = m.canary_paths[0]
    with open(p, "a", encoding="utf-8") as f:
        f.write("secuestrado")

    before = {42: {"name": "evil.exe", "exe": r"C:\Temp\evil.exe",
                   "write_bytes": 0, "write_count": 0}}
    after = {42: {"name": "evil.exe", "exe": r"C:\Temp\evil.exe",
                  "write_bytes": 250, "write_count": 1}}
    m._io_snapshot = before
    monkeypatch.setattr(m, "_read_io_counters", lambda: after)
    monkeypatch.setattr(m, "_processes_with_open_file", lambda path: [])

    m._scan_once()
    assert len(alerts) == 1
    assert alerts[0].event == "modified"
    assert alerts[0].process_pid == 42
    assert alerts[0].process_evidence == "io"
    m.stop_monitoring()
