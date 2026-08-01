"""Tests for YARA rule generation + the staged collection model."""
import config
import argus.yara_gen as yg


def _sample_bytes():
    # MZ header + distinctive behavioral strings + generic noise that must be dropped
    return (b"MZ\x90\x00" + b"\x00" * 60
            + b"This program cannot be run in DOS mode.\x00"
            + b"kernel32.dll\x00GetProcAddress\x00"                 # noise -> dropped
            + b"http://evil-c2.example/gate.php\x00"                # boost
            + b"C:\\Users\\Public\\AppData\\Roaming\\svchost32.exe\x00"  # boost
            + b"powershell -enc SQBFAF\x00"                          # boost
            + b"MUTEX_Zeus_7f3a91\x00")                              # token-ish


def test_extract_and_score(tmp_path):
    data = _sample_bytes()
    strings = yg.extract_strings(data)
    texts = [s for s, _ in strings]
    assert any("evil-c2" in t for t in texts)
    # noise scores <= 0, behavioral strings score > 0
    assert yg._score("kernel32.dll") <= 0
    assert yg._score("This program cannot be run in DOS mode.") <= 0
    assert yg._score("http://evil-c2.example/gate.php") > yg._score("MUTEX_Zeus_7f3a91") - 100


def test_generate_rule(tmp_path):
    f = tmp_path / "mal.exe"
    f.write_bytes(_sample_bytes())
    rule = yg.generate_rule(f, name="mal", meta={"verdict": "suspicious"})
    assert "error" not in rule
    assert rule["name"] == "ARGUS_mal"
    text = rule["text"]
    assert text.startswith("rule ARGUS_mal")
    assert "uint16(0) == 0x5A4D" in text          # PE magic gate
    assert "of ($s*)" in text                      # threshold condition
    assert "evil-c2" in text                       # kept a distinctive string
    assert "kernel32.dll" not in text              # dropped the noise
    assert 'verdict = "suspicious"' in text


def test_too_few_strings():
    import tempfile, os
    fd, path = tempfile.mkstemp()
    os.write(fd, b"MZ" + b"\x00" * 100)  # no distinctive strings
    os.close(fd)
    r = yg.generate_rule(path, name="empty")
    assert r.get("error") and "too few" in r["error"]


def test_collection_roundtrip(tmp_path, monkeypatch):
    # point the ruleset dirs at a temp location
    monkeypatch.setattr(config, "YARA_RULES_DIR", tmp_path / "rules")
    f = tmp_path / "mal.exe"
    f.write_bytes(_sample_bytes())
    rule = yg.generate_rule(f, name="fam")

    staged = yg.save_generated(rule)
    assert staged.exists() and staged.parent.name == "generated"

    listing = yg.list_rules()
    assert "ARGUS_fam.yar" in listing["generated"]
    assert "ARGUS_fam.yar" not in listing["active"]   # staged, not live yet

    res = yg.promote("ARGUS_fam")
    assert res.get("ok")
    listing2 = yg.list_rules()
    assert "ARGUS_fam.yar" in listing2["active"]        # now live
    assert "ARGUS_fam.yar" not in listing2["generated"]  # moved out of staging
