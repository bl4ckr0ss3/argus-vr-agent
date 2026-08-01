"""Regression tests for the dynamic-analysis verdict engine.

Each false-positive class we fixed by hand gets a test here so it can never
silently come back:
  * a lone temp/scratch file must NOT read as a payload drop
  * a truncated/racing Services-hive snapshot must NOT fabricate persistence
  * a genuine new service / Run key MUST still be caught
Plus the newer scoring: confidence bounds and ATT&CK technique tagging, and the
VirusTotal reconciliation logic (with the network call mocked).
"""
import json

import pytest

import argus.tools.dynamic as d
from argus.intel import virustotal


def _mkrun(tmp_path, reg_after="=== after ===\n", files_after="=== after ===\n", csv=None):
    (tmp_path / "registry_before.txt").write_text("=== before ===\n", encoding="utf-8")
    (tmp_path / "registry_after.txt").write_text(reg_after, encoding="utf-8")
    (tmp_path / "files_before.txt").write_text("=== before ===\n", encoding="utf-8")
    (tmp_path / "files_after.txt").write_text(files_after, encoding="utf-8")
    if csv is not None:
        (tmp_path / "procmon.csv").write_text(csv, encoding="utf-8")
    return tmp_path


def _static(name="app.exe", entropy=6.3, sha="a" * 64):
    return {"name": name, "entropy": entropy, "hashes": {"sha256": sha}}


@pytest.fixture(autouse=True)
def _mock_procmon(monkeypatch):
    # Use a written procmon.csv if present; never invoke the real procmon binary.
    monkeypatch.setattr(
        d, "_procmon_to_csv",
        lambda out_dir: (out_dir / "procmon.csv") if (out_dir / "procmon.csv").exists() else None,
    )


def _csv(rows):
    head = '"Process Name","Operation","Path","Detail"\n'
    return head + "".join(f'"{p}","{o}","{path}","x"\n' for p, o, path in rows)


# --- false-positive regressions -------------------------------------------
def test_lone_temp_file_is_benign(tmp_path):
    run = _mkrun(tmp_path, csv=_csv([
        ("app.exe", "WriteFile", "C:/Users/lab/AppData/Local/Temp/abc123.tmp"),
    ]))
    s = d.analyze_detonation(run, _static(), {})
    assert s["verdict"] == "benign"
    assert s["staged_payloads"] == []
    assert "executable-drop" not in s["signals"]


def test_services_flood_does_not_fabricate_persistence(tmp_path):
    flood = ["=== after ==="]
    for i in range(400):
        flood.append(rf"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\.NET CLR Networking {i}")
        flood.append(rf"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\.NET CLR Networking {i}\Linkage")
    run = _mkrun(tmp_path, reg_after="\n".join(flood))
    s = d.analyze_detonation(run, _static(), {})
    assert s["reg_unreliable"] is True
    assert s["persistence"] == []
    assert s["verdict"] != "suspicious"


def test_real_persistence_is_caught(tmp_path):
    reg = "\n".join([
        "=== after ===",
        r"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\EvilSvc",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\Backdoor",
    ])
    run = _mkrun(tmp_path, reg_after=reg, csv=_csv([]))
    s = d.analyze_detonation(run, _static(name="mal.exe"), {})
    assert len(s["persistence"]) == 2
    assert s["verdict"] == "suspicious"
    assert "persistence" in s["signals"]


def test_executable_drop_flags(tmp_path):
    run = _mkrun(tmp_path, csv=_csv([
        ("mal.exe", "WriteFile", "C:/Users/lab/AppData/Roaming/payload.exe"),
    ]))
    s = d.analyze_detonation(run, _static(name="mal.exe"), {})
    assert s["staged_payloads"]
    assert "executable-drop" in s["signals"]
    assert s["verdict"] == "suspicious"


def test_network_signal_flags(tmp_path):
    run = _mkrun(tmp_path, csv=_csv([
        ("mal.exe", "TCP Connect", "labvm:5000 -> 9.9.9.9:443"),
    ]))
    s = d.analyze_detonation(run, _static(name="mal.exe"), {})
    assert s["net"]
    assert "network" in s["signals"]


# --- scoring: confidence + ATT&CK ------------------------------------------
def test_confidence_bounds(tmp_path):
    # benign (procmon parsed, no signals, reliable baseline) -> high
    a = (tmp_path / "a"); a.mkdir()
    benign = d.analyze_detonation(_mkrun(a, csv=_csv([])), _static(), {})
    assert benign["verdict"] == "benign"
    assert benign["confidence"] == 85 and benign["confidence_label"] == "high"

    # inconclusive (no procmon parsed) -> low
    b = (tmp_path / "b"); b.mkdir()
    inc = d.analyze_detonation(_mkrun(b), _static(), {})  # no csv
    assert inc["verdict"] == "inconclusive"
    assert inc["confidence"] == 30 and inc["confidence_label"] == "low"


def test_yara_match_drives_suspicious(tmp_path):
    # A YARA hit alone (clean dynamic run) is enough to flag suspicious with
    # high confidence, and it surfaces the matched rule names.
    run = _mkrun(tmp_path, csv=_csv([]))
    s = d.analyze_detonation(run, dict(_static(name="mal.exe"), yara=["Win_Trojan_Agent"]), {})
    assert "yara-match" in s["signals"]
    assert s["verdict"] == "suspicious"
    assert s["yara"] == ["Win_Trojan_Agent"]
    assert s["confidence"] >= 80


def test_yara_overrides_inconclusive(tmp_path):
    # No procmon parsed (would be 'inconclusive'), but a YARA hit still flags it.
    run = _mkrun(tmp_path)  # no csv -> procmon unparsed
    s = d.analyze_detonation(run, dict(_static(name="mal.exe"), yara=["Ransom_Generic"]), {})
    assert s["procmon_parsed"] is False
    assert s["verdict"] == "suspicious"


def test_reanalyze_run(tmp_path):
    # a run folder whose procmon.csv already exists -> reanalyze parses it and
    # rewrites findings.json without re-detonating
    import json as _json
    run = tmp_path
    for n in ("registry", "files"):
        (run / f"{n}_before.txt").write_text("=== before ===\n", encoding="utf-8")
        (run / f"{n}_after.txt").write_text("=== after ===\n", encoding="utf-8")
    (run / "sample_info.json").write_text(
        _json.dumps({"name": "mal.exe", "entropy": 6.1, "hashes": {"sha256": "a" * 64}}),
        encoding="utf-8")
    (run / "procmon.pml").write_bytes(b"PML\x00" * 10)
    (run / "procmon.csv").write_text(
        '"Process Name","Operation","Path","Detail"\n'
        '"mal.exe","TCP Connect","host:1 -> 5.5.5.5:443","x"\n', encoding="utf-8")
    struct = d.reanalyze_run(run)
    assert "network" in struct["signals"]
    assert (run / "findings.json").exists()
    saved = _json.loads((run / "findings.json").read_text(encoding="utf-8"))
    assert saved["verdict"] == "suspicious"


def test_no_yara_is_unaffected(tmp_path):
    run = _mkrun(tmp_path, csv=_csv([]))
    s = d.analyze_detonation(run, _static(), {})  # no 'yara' key
    assert "yara-match" not in s["signals"]
    assert s["yara"] == []


def test_attack_tags(tmp_path):
    reg = "\n".join([
        "=== after ===",
        r"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\EvilSvc",
    ])
    run = _mkrun(tmp_path, reg_after=reg, csv=_csv([
        ("mal.exe", "TCP Connect", "labvm:5000 -> 9.9.9.9:443"),
        ("mal.exe", "WriteFile", "C:/Users/lab/AppData/Roaming/payload.exe"),
    ]))
    s = d.analyze_detonation(run, _static(name="mal.exe"), {})
    ids = {t["id"] for t in s["attack"]}
    assert "T1071" in ids            # network / C2
    assert "T1105" in ids            # payload drop
    assert "T1543.003" in ids        # new service


# --- VirusTotal reconciliation (network mocked) ----------------------------
def test_vt_noop_without_key(monkeypatch):
    monkeypatch.setattr(virustotal, "available", lambda: False)
    struct = {"verdict": "benign", "sha256": "a" * 64, "confidence": 85}
    assert virustotal.enrich(dict(struct)) == struct  # unchanged


def test_vt_flags_missed_malware(monkeypatch):
    monkeypatch.setattr(virustotal, "available", lambda: True)
    monkeypatch.setattr(virustotal, "lookup",
                        lambda sha: {"found": True, "malicious": 50, "total": 72,
                                     "error": None, "summary": "malicious 50/72"})
    struct = {"verdict": "benign", "sha256": "a" * 64, "confidence": 85}
    out = virustotal.enrich(struct)
    assert "vt_conflict" in out
    assert out["confidence"] >= 70


def test_vt_flags_false_positive(monkeypatch):
    monkeypatch.setattr(virustotal, "available", lambda: True)
    monkeypatch.setattr(virustotal, "lookup",
                        lambda sha: {"found": True, "malicious": 0, "total": 72,
                                     "error": None, "summary": "malicious 0/72"})
    struct = {"verdict": "suspicious", "sha256": "a" * 64, "confidence": 90,
              "signals": ["persistence"]}
    out = virustotal.enrich(struct)
    assert "vt_conflict" in out
    assert out["confidence"] <= 45 and out["confidence_label"] == "low"
