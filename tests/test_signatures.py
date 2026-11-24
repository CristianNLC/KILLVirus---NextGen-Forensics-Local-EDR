"""Tests para core/signatures/store.py"""

import json


from core.signatures import (
    DEFAULT_SEVERITY,
    DEFAULT_SOURCE,
    DictStore,
    SignatureEntry,
    SqliteStore,
    create_signature_store,
)


def _entry(h: str = None, **kw) -> SignatureEntry:
    h = h or "a" * 64
    return SignatureEntry(hash=h, **kw)


def _make_dict(data: dict) -> DictStore:
    return DictStore(data)


def test_dict_store_lookup_found():
    store = _make_dict({"a" * 64: {"malware_name": "Test.Malware"}})
    entry = store.lookup("a" * 64)
    assert entry is not None
    assert entry.malware_name == "Test.Malware"


def test_dict_store_lookup_not_found():
    store = _make_dict({})
    assert store.lookup("b" * 64) is None


def test_dict_store_contains():
    store = _make_dict({"a" * 64: {"malware_name": "X"}})
    assert "a" * 64 in store
    assert "b" * 64 not in store


def test_dict_store_len():
    store = _make_dict({"a" * 64: {"malware_name": "X"}, "b" * 64: {"malware_name": "Y"}})
    assert len(store) == 2


def test_dict_store_items():
    store = _make_dict({"a" * 64: {"malware_name": "X"}})
    items = dict(store.items())
    assert "a" * 64 in items
    assert items["a" * 64].malware_name == "X"


def test_dict_store_add():
    store = DictStore()
    entry = SignatureEntry(hash="c" * 64, malware_name="New")
    store.add(entry)
    assert store.lookup("c" * 64) == entry


def test_dict_store_merge():
    base = _make_dict({"a" * 64: {"malware_name": "A"}})
    other = _make_dict({"b" * 64: {"malware_name": "B"}, "a" * 64: {"malware_name": "A2"}})
    added = base.merge(other)
    assert added == 1  # solo b se añade, a ya existe
    assert base.lookup("a" * 64).malware_name == "A"  # no se sobrescribe
    assert base.lookup("b" * 64).malware_name == "B"


def test_dict_store_to_dict():
    store = _make_dict({"a" * 64: {"malware_name": "X", "threat_type": "T"}})
    d = store.to_dict()
    assert d["a" * 64]["malware_name"] == "X"
    assert d["a" * 64]["threat_type"] == "T"


def test_sqlite_store_crud(tmp_path):
    db = tmp_path / "sigs.db"
    store = SqliteStore(str(db))
    entry = SignatureEntry(hash="b" * 64, malware_name="SQL.Test")
    store.add(entry)
    assert store.lookup("b" * 64) == entry
    assert "b" * 64 in store
    assert len(store) == 1
    items = dict(store.items())
    assert items["b" * 64].malware_name == "SQL.Test"
    store.close()


def test_sqlite_store_persists(tmp_path):
    db = tmp_path / "sigs.db"
    store = SqliteStore(str(db))
    store.add(SignatureEntry(hash="c" * 64, malware_name="Persist"))
    store.close()

    store2 = SqliteStore(str(db))
    assert store2.lookup("c" * 64) is not None
    assert store2.lookup("c" * 64).malware_name == "Persist"
    store2.close()


def test_sqlite_store_merge(tmp_path):
    db = tmp_path / "sigs.db"
    base = SqliteStore(str(db))
    base.add(SignatureEntry(hash="a" * 64, malware_name="A"))

    other = DictStore({"b" * 64: {"malware_name": "B"}})
    added = base.merge(other)
    assert added == 1
    assert base.lookup("b" * 64).malware_name == "B"
    base.close()


def test_create_signature_store_dict():
    store = create_signature_store(":memory:", use_sqlite=False)
    assert isinstance(store, DictStore)
    assert len(store) == 0


def test_create_signature_store_sqlite(tmp_path):
    db = tmp_path / "sigs.db"
    store = create_signature_store(str(db), use_sqlite=True)
    assert isinstance(store, SqliteStore)
    assert len(store) == 0
    store.close()


def test_create_signature_store_migrates_json(tmp_path):
    db = tmp_path / "sigs.db"
    json_file = tmp_path / "sigs.json"
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump({"d" * 64: {"malware_name": "JSON.Test"}}, f)

    store = create_signature_store(str(db), json_path=str(json_file), use_sqlite=True)
    assert len(store) == 1
    assert store.lookup("d" * 64).malware_name == "JSON.Test"
    store.close()


def test_create_signature_store_no_duplicate_on_reopen(tmp_path):
    db = tmp_path / "sigs.db"
    json_file = tmp_path / "sigs.json"
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump({"d" * 64: {"malware_name": "JSON.Test"}}, f)

    store = create_signature_store(str(db), json_path=str(json_file), use_sqlite=True)
    store.add(SignatureEntry(hash="e" * 64, malware_name="Extra"))
    assert len(store) == 2
    store.close()

    store2 = create_signature_store(str(db), json_path=str(json_file), use_sqlite=True)
    assert len(store2) == 2
    store2.close()


def test_defaults():
    assert DEFAULT_SEVERITY == "Critical"
    assert DEFAULT_SOURCE == "local"
