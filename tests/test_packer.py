"""Tests for packer / protector identification."""
import argus.packer as pk


def _static(sections, imports=None, entropy=6.0, high_ent=None):
    return {"entropy": entropy, "pe": {
        "sections": [{"name": n, "entropy": 7.9, "rawsize": 100} for n in sections],
        "imports": imports if imports is not None else ["kernel32.dll", "user32.dll", "advapi32.dll"],
        "high_entropy_sections": high_ent or [],
    }}


def test_upx_by_section():
    r = pk.identify(_static(["UPX0", "UPX1", ".rsrc"], entropy=7.9))
    assert r["packer"] == "UPX" and r["confidence"] == "high"


def test_vmprotect_by_section():
    assert pk.identify(_static([".vmp0", ".vmp1", ".text"], entropy=7.9))["packer"] == "VMProtect"


def test_aspack_by_section():
    assert pk.identify(_static([".text", ".aspack", ".adata"], entropy=7.9))["packer"] == "ASPack"


def test_themida_like_heuristic():
    # randomized section names + high entropy + 1 import -> unknown/custom, medium
    r = pk.identify(_static(["fj3k9d", "a0x1"], imports=["kernel32.dll"],
                            entropy=7.96, high_ent=["fj3k9d"]))
    assert r["packer"] == "unknown/custom" and r["confidence"] == "medium"
    assert any("minimal imports" in i for i in r["indicators"])


def test_clean_binary_not_packed():
    r = pk.identify(_static([".text", ".rdata", ".data", ".rsrc", ".reloc"],
                            imports=["kernel32.dll", "user32.dll", "gdi32.dll", "ole32.dll"],
                            entropy=6.1))
    assert r["packer"] is None


def test_no_pe_no_crash():
    assert pk.identify({})["packer"] is None
    assert pk.identify({"entropy": 7.9, "pe": None})["packer"] in ("unknown/custom", None)
