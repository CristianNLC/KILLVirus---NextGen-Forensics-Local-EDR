"""Tests para core/updater.py (parse_iocs y validaciones)"""


from core.updater import parse_iocs


def _ioc(hash_value, confidence, malware="Test", ioc_type="sha256_hash"):
    return {
        "ioc": hash_value,
        "ioc_type": ioc_type,
        "confidence_level": confidence,
        "malware_printable": malware,
        "threat_type": "Payload",
    }


def test_parse_iocs_only_sha256():
    payload = {
        "query_status": "ok",
        "data": [
            _ioc("a" * 64, 75),
            _ioc("b" * 32, 100, ioc_type="md5_hash"),  # debe ignorarse (md5)
            _ioc("not-a-hash", 100),  # debe ignorarse (no es sha256 válido)
        ],
    }
    result = parse_iocs(payload)
    assert len(result) == 1
    assert "a" * 64 in result


def test_parse_iocs_min_confidence():
    payload = {
        "query_status": "ok",
        "data": [
            _ioc("a" * 64, 75, malware="Alta"),
            _ioc("b" * 64, 25, malware="Baja"),  # < 50, debe ignorarse
        ],
    }
    result = parse_iocs(payload)
    assert len(result) == 1
    assert result["a" * 64]["malware_name"] == "Alta"


def test_parse_iocs_keeps_highest_confidence():
    payload = {
        "query_status": "ok",
        "data": [
            _ioc("a" * 64, 50, malware="Baja confianza"),
            _ioc("a" * 64, 90, malware="Alta confianza"),
        ],
    }
    result = parse_iocs(payload)
    assert len(result) == 1
    assert result["a" * 64]["malware_name"] == "Alta confianza"
    assert result["a" * 64]["confidence"] == 90


def test_parse_iocs_empty_data():
    assert parse_iocs({"query_status": "ok", "data": []}) == {}
    assert parse_iocs({"query_status": "ok"}) == {}
    assert parse_iocs({}) == {}
    assert parse_iocs(None) == {}
    assert parse_iocs("no dict") == {}


def test_parse_iocs_severity():
    payload = {
        "query_status": "ok",
        "data": [
            _ioc("a" * 64, 80),  # >= 75 -> Critical
            _ioc("b" * 64, 60),  # < 75 -> High
        ],
    }
    result = parse_iocs(payload)
    assert result["a" * 64]["severity"] == "Critical"
    assert result["b" * 64]["severity"] == "High"
