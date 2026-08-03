"""Offline tests for VirusTotal freshness reconciliation."""
from datetime import datetime, timedelta

from argus.intel import virustotal


def _date(days_ago: int) -> str:
    return (datetime.now() - timedelta(days=days_ago)).date().isoformat()


def test_fresh_zero_detection_does_not_become_false_positive(monkeypatch):
    monkeypatch.setattr(virustotal, "available", lambda: True)
    monkeypatch.setattr(virustotal, "lookup", lambda _sha: {
        "found": True, "error": None, "malicious": 0, "total": 72,
        "first_seen": _date(2),
    })
    struct = {"sha256": "a" * 64, "verdict": "suspicious", "confidence": 90}
    virustotal.enrich(struct)
    assert "false positive" not in (struct.get("vt_conflict") or "").lower()
    assert "undetected" in struct.get("vt_note", "")
    assert struct["confidence"] == 90


def test_stale_zero_detection_is_flagged(monkeypatch):
    monkeypatch.setattr(virustotal, "available", lambda: True)
    monkeypatch.setattr(virustotal, "lookup", lambda _sha: {
        "found": True, "error": None, "malicious": 0, "total": 72,
        "first_seen": _date(90),
    })
    struct = {"sha256": "b" * 64, "verdict": "suspicious", "confidence": 90}
    virustotal.enrich(struct)
    assert "false positive" in struct["vt_conflict"].lower()
    assert struct["confidence"] == 45
