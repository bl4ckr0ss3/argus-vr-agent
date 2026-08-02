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


def test_pseudo_no_capstone_shape():
    # decompile of empty rows returns an empty-but-valid structure
    out = P.decompile([], "FUN_0", "x64")
    assert out["lines"] == [] and out["text"] == ""
