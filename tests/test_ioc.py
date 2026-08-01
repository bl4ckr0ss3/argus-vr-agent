"""Tests for IOC extraction + defang."""
import argus.ioc as ioc


def _struct():
    return {
        "sha256": "a" * 64,
        "net": ["labvm:52341 -> 93.184.216.34:443",
                "labvm:5 -> 10.0.0.5:80",          # private -> dropped
                "conn to http://evil-c2.example/gate.php"],
        "spawned": ["C:/Windows/System32/cmd.exe"],
        "staged_payloads": ["C:/Users/lab/AppData/Roaming/payload.exe"],
        "persistence": [r"HKEY_LOCAL_MACHINE\...\Run\Updater"],
    }


def _static():
    return {"hashes": {"sha256": "a" * 64, "md5": "b" * 32, "sha1": "c" * 40},
            "iocs": {"mutexes": ["Global\\Locky_7f3"]}}


def test_public_ip_only():
    iocs = ioc.extract_from(_struct(), _static())
    assert iocs["ips"] == ["93.184.216.34"]        # 10.0.0.5 (private) excluded


def test_url_and_domain():
    iocs = ioc.extract_from(_struct(), _static())
    assert "http://evil-c2.example/gate.php" in iocs["urls"]
    assert "evil-c2.example" in iocs["domains"]


def test_file_path_not_a_domain():
    iocs = ioc.extract_from(_struct(), _static())
    # payload.exe must NOT be classified as a domain
    assert not any("payload.exe" in d for d in iocs["domains"])
    assert "C:/Users/lab/AppData/Roaming/payload.exe" in iocs["files"]


def test_hashes_deduped():
    iocs = ioc.extract_from(_struct(), _static())
    assert iocs["hashes"].count("a" * 64) == 1     # sample sha appears once
    assert "b" * 32 in iocs["hashes"] and "c" * 40 in iocs["hashes"]


def test_registry_and_mutex():
    iocs = ioc.extract_from(_struct(), _static())
    assert any("Updater" in r for r in iocs["registry"])
    assert "Global\\Locky_7f3" in iocs["mutexes"]


def test_defang():
    assert ioc.defang("93.184.216.34", "ip") == "93[.]184[.]216[.]34"
    assert ioc.defang("evil.com", "domain") == "evil[.]com"
    assert ioc.defang("http://evil.com/x", "url") == "hxxp://evil[.]com/x"


def test_csv_export():
    iocs = ioc.extract_from(_struct(), _static())
    text = ioc.to_csv(iocs, do_defang=True)
    assert text.splitlines()[0] == "type,indicator"
    assert "93[.]184[.]216[.]34" in text        # defanged in the CSV


def test_empty_struct_no_crash():
    iocs = ioc.extract_from({}, {})
    assert all(v == [] for v in iocs.values())
