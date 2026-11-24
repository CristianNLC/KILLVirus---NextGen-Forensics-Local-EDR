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
