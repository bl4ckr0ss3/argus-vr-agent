"""Tests for the preflight doctor (detection helpers mocked — no real network)."""
import argus.doctor as doc


def _patch(monkeypatch, tools, net, creds):
    monkeypatch.setattr(doc, "detect_tools", lambda: tools)
    monkeypatch.setattr(doc, "detect_network", lambda timeout=3.0: net)
    monkeypatch.setattr(doc, "detect_credentials", lambda: creds)


def test_detonation_ready_isolated(monkeypatch):
    _patch(monkeypatch,
           tools={"procmon": r"C:\T\procmon.exe", "tshark": r"C:\W\tshark.exe", "fakenet": None, "yara_cli": None},
           net={"dns": False, "tcp": False, "fakenet": False, "reachable": False},
           creds={"llm_keys": [], "malwarebazaar": False, "virustotal": False})
    r = doc.assess()
    assert r["readiness"]["detonation"] is True
    assert r["readiness"]["collection"] is False
    assert "isolated" in r["readiness"]["mode"]


def test_detonation_blocked_by_keys(monkeypatch):
    _patch(monkeypatch,
           tools={"procmon": r"C:\T\procmon.exe", "tshark": None, "fakenet": None, "yara_cli": None},
           net={"dns": False, "tcp": False, "fakenet": False, "reachable": False},
           creds={"llm_keys": ["OPENROUTER_API_KEY"], "malwarebazaar": False, "virustotal": False})
    r = doc.assess()
    assert r["readiness"]["detonation"] is False       # keys present -> would block
    cred = [c for c in r["checks"] if c["name"] == "credentials"][0]
    assert cred["status"] == "fail"


def test_detonation_not_ready_while_online(monkeypatch):
    # prereqs met (procmon, no keys) BUT online -> detonation must NOT be ready
    _patch(monkeypatch,
           tools={"procmon": r"C:\T\procmon.exe", "tshark": r"C:\W\tshark.exe", "fakenet": None, "yara_cli": None},
           net={"dns": True, "tcp": True, "fakenet": False, "reachable": True},
           creds={"llm_keys": [], "malwarebazaar": True, "virustotal": False})
    r = doc.assess()
    assert r["readiness"]["detonation"] is False          # online = unsafe
    assert r["readiness"]["detonation_prereqs"] is True    # tools/keys were fine
    assert r["readiness"]["isolated"] is False


def test_collection_ready_online(monkeypatch):
    _patch(monkeypatch,
           tools={"procmon": None, "tshark": None, "fakenet": None, "yara_cli": None},
           net={"dns": True, "tcp": True, "fakenet": False, "reachable": True},
           creds={"llm_keys": [], "malwarebazaar": True, "virustotal": False})
    r = doc.assess()
    assert r["readiness"]["collection"] is True
    assert "collection" in r["readiness"]["mode"]


def test_fakenet_flags_detonation_mode(monkeypatch):
    _patch(monkeypatch,
           tools={"procmon": r"C:\T\procmon.exe", "tshark": None, "fakenet": r"C:\T\fakenet.exe", "yara_cli": None},
           net={"dns": True, "tcp": True, "fakenet": True, "reachable": False},
           creds={"llm_keys": [], "malwarebazaar": True, "virustotal": False})
    r = doc.assess()
    # FakeNet active -> collection NOT ready (can't reach real internet)
    assert r["readiness"]["collection"] is False
    assert "FakeNet" in r["readiness"]["mode"]
    net = [c for c in r["checks"] if c["name"] == "network"][0]
    assert net["status"] == "warn" and "FakeNet" in net["detail"]
