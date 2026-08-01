"""Tests for the selftest validation harness (evaluator + manifest runner)."""
import json

import argus.selftest as st


# --- pure expectation evaluator -------------------------------------------
def test_verdict_match():
    ok, why = st.check_expect({"verdict": "benign"}, {"verdict": "benign"})
    assert ok and not why
    ok, why = st.check_expect({"verdict": "benign"}, {"verdict": "suspicious"})
    assert not ok and why


def test_verdict_not():
    ok, _ = st.check_expect({"verdict_not": "suspicious"}, {"verdict": "benign"})
    assert ok
    ok, _ = st.check_expect({"verdict_not": "suspicious"}, {"verdict": "suspicious"})
    assert not ok


def test_yara_expectations():
    assert st.check_expect({"yara_any": True}, {"yara": ["R1"]})[0]
    assert not st.check_expect({"yara_any": False}, {"yara": ["R1"]})[0]
    assert st.check_expect({"yara_rule": "R1"}, {"yara": ["R1", "R2"]})[0]
    assert not st.check_expect({"yara_rule": "R9"}, {"yara": ["R1"]})[0]


def test_packed_and_signal():
    assert st.check_expect({"packed": True}, {"packed": True})[0]
    assert st.check_expect({"signal": "network"}, {"signals": ["network", "packed"]})[0]
    assert not st.check_expect({"signal": "network"}, {"signals": ["packed"]})[0]


def test_memscan_expectations():
    res = {"hidden_process": True, "hidden_driver": False, "severities": ["CRITICAL"]}
    assert st.check_expect({"hidden_process": True, "severity": "CRITICAL"}, res)[0]
    assert not st.check_expect({"hidden_driver": True}, res)[0]


def test_error_result_fails():
    ok, why = st.check_expect({"verdict": "benign"}, {"error": "missing file"})
    assert not ok and "missing file" in why[0]


def test_unknown_expectation_flagged():
    ok, why = st.check_expect({"bogus": 1}, {"verdict": "benign"})
    assert not ok and "unknown expectation" in why[0]


# --- manifest runner (findings type; no external tools) --------------------
def test_run_manifest_findings(tmp_path):
    run = tmp_path / "run1"; run.mkdir()
    (run / "findings.json").write_text(json.dumps({"verdict": "benign", "signals": []}), encoding="utf-8")
    manifest = {"cases": [
        {"name": "ok-case", "type": "findings", "path": "run1", "expect": {"verdict": "benign"}},
        {"name": "bad-case", "type": "findings", "path": "run1", "expect": {"verdict": "suspicious"}},
    ]}
    mp = tmp_path / "manifest.json"
    mp.write_text(json.dumps(manifest), encoding="utf-8")
    r = st.run_manifest(str(mp))
    assert r["total"] == 2 and r["passed"] == 1 and r["failed"] == 1
    by = {c["name"]: c["status"] for c in r["cases"]}
    assert by["ok-case"] == "pass" and by["bad-case"] == "fail"


def test_run_manifest_missing_file():
    assert "no manifest" in st.run_manifest("does/not/exist.json")["error"]


def test_run_manifest_unknown_type(tmp_path):
    mp = tmp_path / "m.json"
    mp.write_text(json.dumps({"cases": [{"name": "x", "type": "bogus", "expect": {}}]}), encoding="utf-8")
    r = st.run_manifest(str(mp))
    assert r["cases"][0]["status"] == "error"
