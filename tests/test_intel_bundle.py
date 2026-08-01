"""Test the auto intel-bundle writer (IOCs + Sigma per detonation)."""
import argus.tools.dynamic as d


def test_write_intel_bundle(tmp_path):
    struct = {"sample": "mal.exe", "sha256": "a" * 64, "signals": ["network"],
              "net": ["labvm:5 -> 9.9.9.9:443"], "persistence": [r"HKLM\...\Run\X"],
              "spawned": ["cmd.exe"], "staged_payloads": ["C:/x/p.exe"]}
    b = d.write_intel_bundle(tmp_path, struct, {"hashes": {"md5": "b" * 32}})
    assert b["ioc_count"] >= 4 and b["sigma_count"] == 4
    assert (tmp_path / "iocs.json").exists()
    assert (tmp_path / "iocs.csv").exists()
    assert (tmp_path / "sigma.yml").exists()
    assert "9[.]9[.]9[.]9" in (tmp_path / "iocs.csv").read_text()   # defanged


def test_bundle_no_sigma_when_quiet(tmp_path):
    # a quiet run (packed only, no behavioral signals) -> IOCs but no sigma.yml
    struct = {"sample": "x.exe", "sha256": "c" * 64, "signals": ["packed"],
              "net": [], "persistence": [], "spawned": [], "staged_payloads": []}
    b = d.write_intel_bundle(tmp_path, struct, {})
    assert b["sigma_count"] == 0
    assert not (tmp_path / "sigma.yml").exists()
    assert (tmp_path / "iocs.json").exists()
