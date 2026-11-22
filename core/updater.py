"""
Actualización de firmas de hashes desde ThreatFox (abuse.ch).

El endpoint antiguo (`/export/csv/...`) responde HTTP 410 desde que abuse.ch
retiró las exportaciones públicas, así que el actualizador anterior fallaba en
silencio y el antivirus quedaba congelado con un puñado de hashes.

Ahora se usa la Community API oficial:
    POST https://threatfox-api.abuse.ch/api/v1/
    Header: Auth-Key: <clave personal gratuita de https://auth.abuse.ch/>
    Body:   {"query": "get_iocs", "days": 7}

Devuelve como máximo los IOCs de los últimos 7 días, por lo que cada
actualización es incremental y se fusiona con la base local.
"""

import os
import json
import tempfile

import requests

from core.paths import SIGNATURES_FILE, ensure_runtime_dirs

API_URL = "https://threatfox-api.abuse.ch/api/v1/"
MAX_DAYS = 7
MIN_CONFIDENCE = 50  # 0-100; evita IOCs de baja confianza que generan falsos positivos

_HEX = set("0123456789abcdef")


def _valid_hash(value, length):
    return (
        isinstance(value, str)
        and len(value) == length
        and all(c in _HEX for c in value.lower())
    )


def parse_iocs(payload, min_confidence=MIN_CONFIDENCE):
    """Convierte una respuesta de la API en un dict hash -> metadatos.

    Solo se guardan hashes SHA-256 (el motor calcula SHA-256), con confianza
    suficiente y sin duplicados.
    """
    if not isinstance(payload, dict):
        return {}

    data = payload.get("data")
    if not isinstance(data, list):
        return {}

    parsed = {}
    for ioc in data:
        if not isinstance(ioc, dict):
            continue
        if ioc.get("ioc_type") != "sha256_hash":
            continue

        file_hash = (ioc.get("ioc") or "").strip().lower()
        if not _valid_hash(file_hash, 64):
            continue

        try:
            confidence = int(ioc.get("confidence_level") or 0)
        except (TypeError, ValueError):
            confidence = 0
        if confidence < min_confidence:
            continue

        name = ioc.get("malware_printable") or ioc.get("malware") or "ThreatFox.IOC"
        entry = {
            "malware_name": name,
            "threat_type": ioc.get("threat_type") or "Payload",
            "severity": "Critical" if confidence >= 75 else "High",
            "confidence": confidence,
            "first_seen": ioc.get("first_seen") or "",
            "source": "ThreatFox",
        }

        existing = parsed.get(file_hash)
        if existing and existing.get("confidence", 0) >= confidence:
            continue
        parsed[file_hash] = entry

    return parsed


def save_signatures(signatures):
    """Guarda el diccionario de firmas de forma atómica (nunca a medias)."""
    ensure_runtime_dirs()
    directory = os.path.dirname(SIGNATURES_FILE) or "."
    os.makedirs(directory, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix="signatures_", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(signatures, handle, indent=2)
        os.replace(tmp_path, SIGNATURES_FILE)
    except Exception:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise


def update_signatures_from_cloud(current_signatures, auth_key=None, days=MAX_DAYS):
    """
    Descarga IOCs recientes y los fusiona con las firmas locales.

    Retorna: (ok: bool, resultado: int | str, firmas_actualizadas: dict)
    Si ok es True, `resultado` es el número de firmas nuevas.
    """
    auth_key = (auth_key or os.environ.get("THREATFOX_AUTH_KEY") or "").strip()
    if not auth_key:
        return False, (
            "Falta el Auth-Key de abuse.ch. Obtené uno gratis en "
            "https://auth.abuse.ch/ y guardalo en Configuración."
        ), current_signatures

    try:
        days = max(1, min(int(days), MAX_DAYS))
    except (TypeError, ValueError):
        days = MAX_DAYS

    try:
        response = requests.post(
            API_URL,
            headers={"Auth-Key": auth_key, "Accept": "application/json"},
            json={"query": "get_iocs", "days": days},
            timeout=30,
        )
    except requests.RequestException as e:
        return False, f"Error de red: {e}", current_signatures

    if response.status_code in (401, 403):
        return False, "Auth-Key rechazada por abuse.ch (verificala en auth.abuse.ch).", current_signatures
    if response.status_code == 429:
        return False, "Límite de consultas alcanzado. Intentá más tarde.", current_signatures
    if response.status_code != 200:
        return False, f"La API respondió HTTP {response.status_code}.", current_signatures

    try:
        payload = response.json()
    except ValueError:
        return False, "Respuesta inválida de la API (no es JSON).", current_signatures

    status = payload.get("query_status") if isinstance(payload, dict) else None
    if status != "ok":
        return False, f"La API devolvió estado '{status}'.", current_signatures

    new_entries = parse_iocs(payload)
    merged = dict(current_signatures or {})
    added = 0
    for file_hash, entry in new_entries.items():
        if file_hash not in merged:
            added += 1
        merged[file_hash] = entry

    try:
        save_signatures(merged)
    except Exception as e:
        return False, f"No se pudo guardar la base de firmas: {e}", current_signatures

    return True, added, merged
