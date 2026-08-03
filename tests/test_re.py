"""Tests for the reverse-engineering workspace backend (argus.re)."""
import struct

import pytest

from argus.re import container as C
from argus.re import disasm as D
from argus.re import pseudo as P
from argus.re import session as S


# --- a hand-built minimal PE so tests don't need a real binary on disk ------
def _tiny_pe() -> bytes:
    """Smallest PE that our parser accepts: DOS stub + PE + 1 section of code."""
    code = b"\x48\x83\xec\x28\x48\xc7\xc0\x01\x00\x00\x00\x48\x83\xc4\x28\xc3"  # sub;mov rax,1;add;ret
    data = bytearray(0x400)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)  # e_lfanew
    off = 0x80
    data[off:off + 4] = b"PE\x00\x00"
    coff = off + 4
    # machine x64, 1 section, timestamp 0, opt header size 0xF0, chars
    struct.pack_into("<HHIIIHH", data, coff, 0x8664, 1, 0, 0, 0, 0xF0, 0x22)
    opt = coff + 20
    struct.pack_into("<H", data, opt, 0x20B)      # PE32+
    struct.pack_into("<I", data, opt + 16, 0x1000)  # entry rva
    struct.pack_into("<Q", data, opt + 24, 0x140000000)  # image base
    # data directories are zero (no imports/exports) -> fine
    sec = opt + 0xF0
    name = b".text\x00\x00\x00"
    data[sec:sec + 8] = name
    struct.pack_into("<IIII", data, sec + 8, len(code), 0x1000, 0x200, 0x200)  # vsize,vaddr,rawsize,rawptr
    struct.pack_into("<I", data, sec + 36, 0x60000020)  # CODE|EXEC|READ
    data[0x200:0x200 + len(code)] = code
    return bytes(data)


def test_parse_pe_basic():
    b = C.parse(_tiny_pe())
    assert b is not None
    assert b["format"] == "PE"
    assert b["arch"] == "x64" and b["bits"] == 64
    assert b["entry"] == 0x140001000
    assert any(s["name"] == ".text" and "x" in s["perm"] for s in b["sections"])


def test_va_off_roundtrip():
    b = C.parse(_tiny_pe())
    off = C.va_to_off(b, 0x140001000)
    assert off == 0x200
    assert C.off_to_va(b, off) == 0x140001000


def test_reject_garbage():
    assert C.parse(b"not an executable at all") is None


@pytest.mark.skipif(not D.HAVE_CAPSTONE, reason="capstone not installed")
def test_disassemble_and_flow():
    b = C.parse(_tiny_pe())
    md = D.make_engine(b["arch"], b["bits"])
    off = C.va_to_off(b, b["entry"])
    rows = D.disassemble(_tiny_pe(), off, b["entry"], 10, md)
    mnem = [r["mnemonic"] for r in rows]
    assert "sub" in mnem and "mov" in mnem
    # the ret is present and classified as flow=='ret'
    assert any(r["mnemonic"] == "ret" and r["flow"] == "ret" for r in rows)


@pytest.mark.skipif(not D.HAVE_CAPSTONE, reason="capstone not installed")
def test_session_load_and_decompile():
    sess = S.Session("tiny.exe", _tiny_pe())
    summ = sess.summary()
    assert summ["format"] == "PE"
    assert summ["counts"]["functions"] >= 1
    dec = sess.decompile(sess.functions[0]["addr"])
    assert dec["error"] is None
    assert any("return" in ln["text"] or "ret" in ln["text"] for ln in dec["lines"])


@pytest.mark.skipif(not D.HAVE_KEYSTONE, reason="keystone not installed")
def test_assemble_roundtrip():
    r = D.assemble("mov rax, 1; ret", "x64", 64)
    assert r["ok"] and r["hex"] == "48c7c001000000c3"


@pytest.mark.skipif(not D.HAVE_KEYSTONE, reason="keystone not installed")
def test_assemble_error_is_graceful():
    r = D.assemble("this is not asm", "x64", 64)
    assert r["ok"] is False and "error" in r


def test_hexdump_and_strings():
    sess = S.Session("tiny.exe", _tiny_pe())
    hd = sess.hexdump(0, 16)
    assert hd["rows"][0]["ascii"].startswith("MZ")
    # our tiny PE has ".text" as an ascii string
    assert any(".text" in s["text"] for s in sess.strings(minlen=4))


def _tiny_pe32_with_import() -> bytes:
    """Minimal 32-bit (PE32) exe with a real import from KERNEL32.dll.

    Layout: DOS stub | PE | 1 code section (.text @RVA 0x1000/raw 0x200) and
    the import table placed inside the .data section so we can point the
    Import Directory at it. Thunks are 4-byte on PE32 — this is exactly the
    case the old parser misread (it always walked 8-byte thunks).
    """
    import struct as _st
    data = bytearray(0x800)
    data[0:2] = b"MZ"
    _st.pack_into("<I", data, 0x3C, 0x80)
    off = 0x80
    data[off:off + 4] = b"PE\x00\x00"
    coff = off + 4
    # machine x86, 1 section, timestamp 0, opt size 0xE0, chars
    _st.pack_into("<HHIIIHH", data, coff, 0x14C, 1, 0, 0, 0, 0xE0, 0x22)
    opt = coff + 20
    _st.pack_into("<H", data, opt, 0x10B)           # PE32
    _st.pack_into("<I", data, opt + 16, 0x1000)     # entry rva
    _st.pack_into("<I", data, opt + 24, 0x400000)   # image base
    # data directory [1] = import table @ RVA 0x2000
    _st.pack_into("<I", data, opt + 96 + 8, 0x2000)

    # .data section: rva 0x2000 -> raw 0x400, spanning 0x200 bytes (covers the
    # whole import table structure below with consistent RVA/raw mapping).
    sec = opt + 0xE0
    data[sec:sec + 8] = b".data\x00\x00\x00"
    _st.pack_into("<IIIII", data, sec + 8, 0x200, 0x2000, 0x200, 0x400, 0x60000040)
    # raw off X maps to rva 0x2000 + (X - 0x400)

    # --- build the import table inside .data (all RVAs map inside the section) ---
    desc = 0x400   # rva 0x2000
    ilt  = 0x430   # rva 0x2030
    dlln = 0x450   # rva 0x2050
    hint = 0x470   # rva 0x2070
    _st.pack_into("<I", data, desc + 0, 0x2030)   # OriginalFirstThunk -> ILT
    _st.pack_into("<I", data, desc + 4, 0)        # TimeDateStamp
    _st.pack_into("<I", data, desc + 8, 0)        # ForwarderChain
    _st.pack_into("<I", data, desc + 12, 0x2050)  # Name -> "KERNEL32.dll"
    _st.pack_into("<I", data, desc + 16, 0x2030)  # FirstThunk -> IAT
    _st.pack_into("<I", data, desc + 20, 0)       # null terminator descriptor

    data[ilt:ilt + 4] = _st.pack("<I", 0x2070)    # ILT[0] -> hint/name
    data[ilt + 4:ilt + 8] = _st.pack("<I", 0)     # ILT[1] = end
    data[dlln:dlln + 12] = b"KERNEL32.dll\x00"
    data[hint:hint + 2] = _st.pack("<H", 0x0100)  # hint
    data[hint + 2:hint + 13] = b"MessageBoxA\x00"
    return bytes(data)


def test_pe32_import_thunk_width():
    """Regression: 32-bit PE import thunks are 4 bytes, not 8."""
    raw = _tiny_pe32_with_import()
    b = C.parse(raw)
    assert b is not None, "parser should accept the hand-built PE32"
    assert b["arch"] == "x86" and b["bits"] == 32
    names = [(i["lib"], i["name"]) for i in b.get("imports", [])]
    assert any(lib == "KERNEL32.dll" for lib, _ in names), f"expected KERNEL32.dll import, got {names}"
    assert any(n == "MessageBoxA" for _, n in names), f"expected MessageBoxA, got {names}"


def test_pseudo_no_capstone_shape():
    # decompile of empty rows returns an empty-but-valid structure
    out = P.decompile([], "FUN_0", "x64")
    assert out["lines"] == [] and out["text"] == ""


def test_session_cache_bounded():
    """Loading many distinct binaries must not grow the session cache unboundedly."""
    old_max = S._SESSION_CACHE_MAX
    S._SESSION_CACHE_MAX = 3
    try:
        for i in range(6):
            b = _tiny_pe()
            # vary content hash so each load is a distinct session
            b = b[:0x100] + bytes([i % 251]) + b[0x101:]
            lr = S.load_binary(f"s{i}.exe", b)
            assert "error" not in lr
        assert len(S._SESSIONS) <= 3, f"cache grew to {len(S._SESSIONS)} (max 3)"
    finally:
        S._SESSION_CACHE_MAX = old_max
