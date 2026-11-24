"""Tests para core/autoprotect.py."""

import json

from core.autoprotect import (
    _dacl_protected,
    acl_is_hardened,
    build_icacls_command,
    compute_manifest,
    protection_status,
    verify_manifest,
    write_manifest,
)


def test_build_icacls_command_disables_inheritance():
    command = build_icacls_command(r"C:\datos", user="*S-1-5-21-1")
    assert command[0] == "icacls"
    assert command[1] == r"C:\datos"
    assert "/inheritance:r" in command
    assert "/T" in command
    assert any("/grant:r" in part for part in command)
    assert any("*S-1-5-18" in part for part in command)
    assert any("*S-1-5-32-544" in part for part in command)


def test_acl_detection_returns_bool_or_none(tmp_path):
    value = _dacl_protected(str(tmp_path))
    assert value is None or isinstance(value, bool)
    assert isinstance(acl_is_hardened(str(tmp_path)), bool)


def test_acl_detection_missing_path():
    assert acl_is_hardened(r"C:\ruta\que\no\existe") is False


def test_protection_status_shape():
    status = protection_status()
    assert isinstance(status["admin"], bool)
    assert isinstance(status["dirs"], dict)
    assert isinstance(status["hardened"], bool)


def test_manifest_roundtrip_and_change_detection(tmp_path):
    core_dir = tmp_path / "core"
    core_dir.mkdir()
    (core_dir / "modulo.py").write_text("x = 1\n", encoding="utf-8")
    (core_dir / "__pycache__").mkdir()
    (core_dir / "__pycache__" / "basura.py").write_text("ignorar", encoding="utf-8")

    manifest = compute_manifest(str(tmp_path))
    assert "core\\modulo.py" in manifest["files"] or "core/modulo.py" in manifest["files"]
    assert not any("__pycache__" in key for key in manifest["files"])

    target = tmp_path / "integrity.json"
    write_manifest(str(target), str(tmp_path))
    assert verify_manifest(str(target), str(tmp_path)) == []

    (core_dir / "modulo.py").write_text("x = 2\n", encoding="utf-8")
    problems = verify_manifest(str(target), str(tmp_path))
    assert any("modificado" in problem for problem in problems)

    (core_dir / "modulo.py").unlink()
    problems = verify_manifest(str(target), str(tmp_path))
    assert any("desaparecido" in problem for problem in problems)


def test_verify_manifest_without_file(tmp_path):
    problems = verify_manifest(str(tmp_path / "no-existe.json"), str(tmp_path))
    assert problems and "No existe" in problems[0]


def test_verify_manifest_invalid_json(tmp_path):
    target = tmp_path / "integrity.json"
    target.write_text("no es json", encoding="utf-8")
    problems = verify_manifest(str(target), str(tmp_path))
    assert problems


def test_manifest_is_json_serializable(tmp_path):
    (tmp_path / "app.py").write_text("print('hola')\n", encoding="utf-8")
    manifest = compute_manifest(str(tmp_path))
    payload = json.dumps(manifest)
    assert "app.py" in payload
