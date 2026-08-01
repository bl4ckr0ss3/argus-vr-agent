"""Tests for the boot-chain differential (pure diff logic; no real device access)."""
import argus.bootscan as bs


def _cap(**over):
    base = {
        "admin": True,
        "mbr": "a" * 64, "vbr": "b" * 64, "secure_boot": "on",
        "esp_files": {"efi/microsoft/boot/bootmgfw.efi": "c" * 64},
        "bcd": "Windows Boot Manager\n  path bootmgfw.efi\n",
        "bcd_firmware": "", "drivers": {"tcpip": {"start": "Boot", "state": "Running", "path": "tcpip.sys"}},
    }
    base.update(over)
    return base


def test_no_change():
    assert bs._diff(_cap(), _cap()) == []


def test_mbr_change_is_critical():
    f = bs._diff(_cap(), _cap(mbr="z" * 64))
    assert any(x["severity"] == "CRITICAL" and "MBR" in x["what"] for x in f)


def test_secure_boot_off_is_critical():
    f = bs._diff(_cap(), _cap(secure_boot="off"))
    assert any(x["severity"] == "CRITICAL" and "Secure Boot" in x["what"] for x in f)


def test_esp_binary_modified_is_high():
    after = _cap(esp_files={"efi/microsoft/boot/bootmgfw.efi": "DIFFERENT"})
    f = bs._diff(_cap(), after)
    assert any(x["severity"] == "HIGH" and "ESP file modified" in x["what"] for x in f)


def test_new_esp_file_flagged():
    after = _cap(esp_files={"efi/microsoft/boot/bootmgfw.efi": "c" * 64,
                            "efi/boot/rootkit.efi": "x" * 64})
    f = bs._diff(_cap(), after)
    assert any("ESP file added" in x["what"] and "rootkit.efi" in x["detail"] for x in f)


def test_new_boot_driver_is_high():
    after = _cap(drivers={"tcpip": {"start": "Boot", "state": "Running", "path": "tcpip.sys"},
                          "evilrk": {"start": "System", "state": "Running", "path": "evilrk.sys"}})
    f = bs._diff(_cap(), after)
    hit = [x for x in f if x["what"] == "new driver loaded" and "evilrk" in x["detail"]]
    assert hit and hit[0]["severity"] == "HIGH"


def test_new_manual_driver_is_medium():
    after = _cap(drivers={"tcpip": {"start": "Boot", "state": "Running", "path": "tcpip.sys"},
                          "usbthing": {"start": "Manual", "state": "Stopped", "path": "usb.sys"}})
    f = bs._diff(_cap(), after)
    hit = [x for x in f if "usbthing" in x["detail"]]
    assert hit and hit[0]["severity"] == "MEDIUM"


def test_bcd_testsigning_flagged():
    after = _cap(bcd="Windows Boot Loader\n  testsigning Yes\n")
    f = bs._diff(_cap(), after)
    assert any("integrity weakened" in x["what"] and "testsigning" in x["detail"] for x in f)


def test_findings_ranked_critical_first():
    after = _cap(mbr="z" * 64,
                 drivers={"tcpip": {"start": "Boot", "state": "Running", "path": "tcpip.sys"},
                          "d2": {"start": "Manual", "state": "Stopped", "path": "d2.sys"}})
    f = bs._diff(_cap(), after)
    assert f[0]["severity"] == "CRITICAL"
