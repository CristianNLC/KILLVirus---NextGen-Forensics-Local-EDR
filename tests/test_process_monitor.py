"""Tests para core/process_monitor.py (con mocks)"""

from unittest.mock import MagicMock, patch


from core.process_monitor import ProcessMonitor


@patch("core.process_monitor.psutil.process_iter")
def test_process_monitor_seeds_known_pids(mock_iter):
    mock_proc = MagicMock()
    mock_proc.info = {"pid": 123}
    mock_iter.return_value = [mock_proc]

    store = MagicMock()
    pm = ProcessMonitor(store)
    assert 123 in pm._known_pids


@patch("core.process_monitor.psutil.process_iter")
@patch("core.process_monitor.os.path.isfile", return_value=True)
def test_process_monitor_detects_new_malicious_process(mock_isfile, mock_iter):
    # Primer llamada: seed (ningún proceso)
    # Segunda llamada: un proceso nuevo con firma maliciosa
    mock_new_proc = MagicMock()
    mock_new_proc.info = {
        "pid": 999,
        "name": "evil.exe",
        "exe": r"C:\Temp\evil.exe",
        "cmdline": ["C:\\Temp\\evil.exe"],
        "create_time": 12345,
        "username": "user",
    }

    mock_iter.side_effect = [[], [mock_new_proc]]

    alerts = []
    store = MagicMock()
    store.lookup.return_value = MagicMock(malware_name="Test.Malware")
    import core.process_monitor as pm_mod

    # Mock calculate_sha256 para retornar un hash
    with patch.object(pm_mod, "calculate_sha256", return_value="a" * 64):
        pm = ProcessMonitor(store, on_detect=alerts.append, interval=0.01)
        pm._scan_once()

    assert len(alerts) == 1
    assert alerts[0]["pid"] == 999
    assert alerts[0]["malware"] == "Test.Malware"
