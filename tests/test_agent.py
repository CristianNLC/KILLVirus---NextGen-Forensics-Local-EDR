"""Tests para core/agent.py (agente headless)."""

import json
import os
import time

import pytest

from core.agent import AgentOptions, ProtectionAgent, default_watch_folders
from core.signatures import DictStore


@pytest.fixture()
def agent(tmp_path, monkeypatch):
    # La cuarentena real no debe usarse en tests.
    import core.quarantine as quarantine

    monkeypatch.setattr(quarantine, "QUARANTINE_DIR", str(tmp_path / "cuarentena"))
    os.makedirs(tmp_path / "cuarentena", exist_ok=True)

    workdir = tmp_path / "user"
    workdir.mkdir()
    status_file = tmp_path / "status.json"
    options = AgentOptions(
        watch_folders=[str(workdir)],
        canary_dirs=[str(workdir)],
        enable_process_monitor=False,
        canary_interval=0.2,
        heartbeat_interval=0.2,
        watchdog_interval=5.0,
        status_file=str(status_file),
    )
    instance = ProtectionAgent(options, store=DictStore())
    yield instance, workdir, status_file
    instance.stop()


def test_agent_starts_and_writes_status(agent):
    instance, _workdir, status_file = agent
    instance.start()
    deadline = time.time() + 3
    while time.time() < deadline and not status_file.exists():
        time.sleep(0.05)

    assert instance.is_running
    assert status_file.exists()
    data = json.loads(status_file.read_text(encoding="utf-8"))
    assert data["running"] is True
    assert data["components"]["live_protection"] is True
    assert data["components"]["canary"] is True
    assert data["components"]["process_monitor"] is False


def test_agent_stop_is_idempotent(agent):
    instance, _workdir, _status_file = agent
    instance.start()
    instance.stop()
    assert not instance.is_running
    instance.stop()  # no debe lanzar


def test_agent_quarantines_detection(agent, tmp_path):
    instance, workdir, _status_file = agent

    class FakeDetection:
        name = "Test.Agent"
        reason = "Firma de prueba"
        sha256 = "a" * 64

    victim = workdir / "malware.exe"
    victim.write_bytes(b"MZ prueba")

    instance.start()
    instance._on_detect(str(victim), FakeDetection())

    deadline = time.time() + 3
    while time.time() < deadline and instance.status()["stats"]["detections"] == 0:
        time.sleep(0.05)

    stats = instance.status()["stats"]
    assert stats["detections"] == 1
    assert stats["quarantined"] == 1
    assert not victim.exists()
    quarantined = list((tmp_path / "cuarentena").iterdir())
    assert any(p.name.endswith(".exe.quarantine") or p.suffix == ".quarantine" for p in quarantined)


def test_agent_options_from_config(tmp_path):
    folder = tmp_path / "Downloads"
    folder.mkdir()
    options = AgentOptions.from_config(
        {
            "agent": {
                "watch_folders": [str(folder), str(tmp_path / "no-existe")],
                "enable_canary": False,
                "enable_process_monitor": False,
                "quarantine_detections": False,
            }
        }
    )
    assert options.watch_folders == [str(folder)]
    assert options.enable_canary is False
    assert options.enable_process_monitor is False
    assert options.quarantine_detections is False


def test_agent_options_tolerates_bad_config():
    options = AgentOptions.from_config({"agent": "no-es-dict"})
    assert isinstance(options.watch_folders, list)


def test_default_watch_folders_returns_existing_dirs():
    for folder in default_watch_folders():
        assert os.path.isdir(folder)


def test_effective_profile_for_system_service(monkeypatch, tmp_path):
    from core.agent import _effective_profile

    profile = tmp_path / "Ana"
    data_dir = profile / "AppData" / "Local" / "KILLVirus"
    monkeypatch.setenv("USERPROFILE", r"C:\Windows\system32\config\systemprofile")
    monkeypatch.setenv("USERNAME", "SYSTEM")
    monkeypatch.setenv("KILLVIRUS_DATA_DIR", str(data_dir))
    assert _effective_profile() == str(profile)


def test_effective_profile_from_data_dir_without_system(monkeypatch, tmp_path):
    from core.agent import _effective_profile

    profile = tmp_path / "Ana"
    monkeypatch.setenv("USERPROFILE", r"C:\Users\Otro")
    monkeypatch.setenv("USERNAME", "Otro")
    monkeypatch.setenv(
        "KILLVIRUS_DATA_DIR", str(profile / "AppData" / "Local" / "KILLVirus")
    )
    assert _effective_profile() == str(profile)


def test_effective_profile_uses_userprofile_for_normal_user(monkeypatch, tmp_path):
    from core.agent import _effective_profile

    monkeypatch.setenv("USERPROFILE", str(tmp_path / "Usuario"))
    monkeypatch.setenv("USERNAME", "Usuario")
    monkeypatch.setenv("KILLVIRUS_DATA_DIR", str(tmp_path / "datos"))
    assert _effective_profile() == str(tmp_path / "Usuario")
