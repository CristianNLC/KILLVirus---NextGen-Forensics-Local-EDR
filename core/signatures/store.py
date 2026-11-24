"""Almacenamiento de firmas de malware.

La idea es abstraer el backend (JSON en memoria hoy, SQLite mañana) para que
el motor de detección no dependa de un dict suelto. Cualquier objeto que
implemente esta interfaz se puede pasar a scan_file() y a los colectores.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from dataclasses import dataclass
from typing import Iterable, Optional, Protocol, runtime_checkable

DEFAULT_SEVERITY = "Critical"
DEFAULT_SOURCE = "local"

SCHEMA_VERSION = 1


@dataclass(frozen=True)
class SignatureEntry:
    hash: str
    malware_name: str
    threat_type: str = ""
    severity: str = DEFAULT_SEVERITY
    source: str = DEFAULT_SOURCE
    first_seen: str = ""
    confidence: int = 0

    def to_dict(self) -> dict:
        return {
            "malware_name": self.malware_name,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "source": self.source,
            "first_seen": self.first_seen,
            "confidence": self.confidence,
        }


@runtime_checkable
class SignatureStore(Protocol):
    """Interfaz de consulta y escritura de firmas por hash SHA-256."""

    def lookup(self, file_hash: str) -> Optional[SignatureEntry]:
        """Devuelve la entrada si el hash existe, None si no."""

    def __len__(self) -> int: ...

    def __contains__(self, file_hash: object) -> bool: ...

    def items(self) -> Iterable[tuple[str, SignatureEntry]]: ...

    def add(self, entry: SignatureEntry) -> None: ...

    def merge(self, other: "SignatureStore") -> int: ...

    def to_dict(self) -> dict: ...


class DictStore:
    """Implementación en memoria. Es la que usa la app hoy en día."""

    def __init__(self, data: Optional[dict[str, dict]] = None):
        self._entries: dict[str, SignatureEntry] = {}
        if data:
            for file_hash, meta in data.items():
                if not isinstance(meta, dict):
                    continue
                key = str(file_hash).lower()
                self._entries[key] = SignatureEntry(
                    hash=key,
                    malware_name=meta.get("malware_name", "Malware"),
                    threat_type=meta.get("threat_type", ""),
                    severity=meta.get("severity", DEFAULT_SEVERITY),
                    source=meta.get("source", DEFAULT_SOURCE),
                    first_seen=meta.get("first_seen", ""),
                    confidence=meta.get("confidence", 0),
                )

    def lookup(self, file_hash: str) -> Optional[SignatureEntry]:
        return self._entries.get((file_hash or "").lower())

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, file_hash: object) -> bool:
        if not isinstance(file_hash, str):
            return False
        return file_hash.lower() in self._entries

    def items(self) -> Iterable[tuple[str, SignatureEntry]]:
        return self._entries.items()

    def add(self, entry: SignatureEntry) -> None:
        self._entries[entry.hash] = entry

    def merge(self, other: "SignatureStore") -> int:
        added = 0
        for file_hash, entry in other.items():
            if file_hash not in self:
                self.add(entry)
                added += 1
        return added

    def to_dict(self) -> dict:
        return {h: e.to_dict() for h, e in self._entries.items()}


class SqliteStore:
    """Implementación sobre SQLite (estructura preparada; se activa cuando se desee).

    Guarda una tabla signatures(hash TEXT PRIMARY KEY, metadata JSON).
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        # check_same_thread=False + lock: la UI consulta el store desde el hilo
        # de escaneo y desde el hilo principal. WAL + busy_timeout permite que
        # el servicio de Windows y la interfaz usen la misma base a la vez.
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(db_path, timeout=30.0, check_same_thread=False)
        try:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA busy_timeout=30000")
        except sqlite3.DatabaseError:
            pass
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS signatures (
                hash TEXT PRIMARY KEY,
                metadata TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def lookup(self, file_hash: str) -> Optional[SignatureEntry]:
        with self._lock:
            row = self._conn.execute(
                "SELECT metadata FROM signatures WHERE hash = ?",
                ((file_hash or "").lower(),),
            ).fetchone()
        if not row:
            return None
        meta = json.loads(row[0])
        return SignatureEntry(hash=(file_hash or "").lower(), **meta)

    def __len__(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) FROM signatures").fetchone()
        return int(row[0]) if row else 0

    def __contains__(self, file_hash: object) -> bool:
        if not isinstance(file_hash, str):
            return False
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM signatures WHERE hash = ? LIMIT 1",
                (file_hash.lower(),),
            ).fetchone()
        return row is not None

    def items(self) -> Iterable[tuple[str, SignatureEntry]]:
        with self._lock:
            rows = self._conn.execute("SELECT hash, metadata FROM signatures").fetchall()
        for hash_val, metadata in rows:
            meta = json.loads(metadata)
            yield hash_val, SignatureEntry(hash=hash_val.lower(), **meta)

    def add(self, entry: SignatureEntry) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO signatures (hash, metadata) VALUES (?, ?)",
                (entry.hash, json.dumps(entry.to_dict())),
            )
            self._conn.commit()

    def merge(self, other: "SignatureStore") -> int:
        added = 0
        for file_hash, entry in other.items():
            if file_hash not in self:
                self.add(entry)
                added += 1
        return added

    def to_dict(self) -> dict:
        return {h: e.to_dict() for h, e in self.items()}

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def migrate_from_json(json_path: str, store: SqliteStore) -> int:
    """Importa las firmas de un archivo JSON (dict hash -> metadatos) a SQLite.

    Solo importa si la tabla está vacía, para no duplicar datos en cada arranque.
    Retorna cuántas entradas se insertaron.
    """
    if not os.path.isfile(json_path):
        return 0

    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return 0

    if not isinstance(data, dict):
        return 0

    # Si ya hay datos en SQLite, no reimportar.
    if len(store) > 0:
        return 0

    count = 0
    for file_hash, meta in data.items():
        if not isinstance(meta, dict):
            continue
        entry = SignatureEntry(
            hash=str(file_hash).lower(),
            malware_name=meta.get("malware_name", "Malware"),
            threat_type=meta.get("threat_type", ""),
            severity=meta.get("severity", DEFAULT_SEVERITY),
            source=meta.get("source", DEFAULT_SOURCE),
            first_seen=meta.get("first_seen", ""),
            confidence=meta.get("confidence", 0),
        )
        store.add(entry)
        count += 1
    return count


def create_signature_store(
    db_path: str,
    json_path: Optional[str] = None,
    use_sqlite: bool = True,
) -> SignatureStore:
    """Crea el store de firmas adecuado.

    Por defecto usa SQLite si está disponible. Si `json_path` se provee y la BD
    está vacía, se importa el JSON la primera vez.
    """
    if use_sqlite:
        store = SqliteStore(db_path)
        if json_path:
            migrated = migrate_from_json(json_path, store)
            if migrated:
                import logging

                logging.getLogger(__name__).info(
                    "Migradas %d firmas de JSON a SQLite", migrated
                )
        return store
    data = {}
    if json_path and os.path.isfile(json_path):
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {}
    return DictStore(data)

