"""Executable container parsing — PE and ELF — in pure stdlib.

Produces a uniform `Binary` dict the rest of the RE backend consumes:

    {
      "format": "PE" | "ELF",
      "arch": "x86" | "x64" | "arm" | "arm64" | "?",
      "bits": 32 | 64,
      "entry": <int VA>,
      "image_base": <int>,
      "sections":  [{name, va, vsize, rawptr, rawsize, perm, type, entropy}],
      "symbols":   [{addr, name, type}],   # type: function | data | external | ...
      "imports":   [{name, lib}],
      "exports":   [{addr, name}],
    }

va<->file-offset translation is exposed via `va_to_off` / `off_to_va` bound to
the parsed sections, so the disassembler and hex view can seek by address.
"""
from __future__ import annotations

import math
import struct
from collections import Counter


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return round(-sum((c / n) * math.log2(c / n) for c in counts.values()), 2)


def _cstr(data: bytes, off: int, limit: int = 512) -> str:
    end = data.find(b"\x00", off, off + limit)
    if end == -1:
        end = min(off + limit, len(data))
    return data[off:end].decode("latin1", "ignore")


# ===========================================================================
# PE
# ===========================================================================
_PE_MACHINES = {0x14C: ("x86", 32), 0x8664: ("x64", 64),
                0x1C0: ("arm", 32), 0x1C4: ("arm", 32), 0xAA64: ("arm64", 64)}


def _pe_perm(chars: int) -> str:
    r = "r" if chars & 0x40000000 else "-"
    w = "w" if chars & 0x80000000 else "-"
    x = "x" if chars & 0x20000000 else "-"
    return r + w + x


def parse_pe(data: bytes) -> dict | None:
    if data[:2] != b"MZ" or len(data) < 0x40:
        return None
    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return None
        coff = e_lfanew + 4
        machine, nsec = struct.unpack_from("<HH", data, coff)
        opt = coff + 20
        magic = struct.unpack_from("<H", data, opt)[0]
        is_plus = magic == 0x20B
        arch, bits = _PE_MACHINES.get(machine, ("?", 32 if not is_plus else 64))
        entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
        image_base = (struct.unpack_from("<Q", data, opt + 24)[0] if is_plus
                      else struct.unpack_from("<I", data, opt + 28)[0])
        opt_size = struct.unpack_from("<H", data, coff + 16)[0]
        sec_off = opt + opt_size

        sections = []
        for i in range(min(nsec, 96)):
            base = sec_off + i * 40
            if base + 40 > len(data):
                break
            name = data[base:base + 8].split(b"\x00")[0].decode("latin1", "ignore")
            vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, base + 8)
            chars = struct.unpack_from("<I", data, base + 36)[0]
            raw = data[rawptr:rawptr + rawsize] if rawsize else b""
            sections.append({
                "name": name or f"sect_{i}", "va": image_base + vaddr, "rva": vaddr,
                "vsize": vsize, "rawptr": rawptr, "rawsize": rawsize,
                "perm": _pe_perm(chars), "type": "CODE" if chars & 0x20 else "DATA",
                "entropy": _entropy(raw),
            })

        dd = opt + (112 if is_plus else 96)
        imports = _pe_imports(data, struct.unpack_from("<I", data, dd + 8)[0],
                              sections, image_base)
        exports = _pe_exports(data, struct.unpack_from("<I", data, dd)[0],
                              sections, image_base)

        symbols = [{"addr": e["addr"], "name": e["name"], "type": "export"} for e in exports]
        symbols += [{"addr": 0, "name": f"{i['lib']}::{i['name']}", "type": "external"}
                    for i in imports]

        return {
            "format": "PE", "arch": arch, "bits": bits,
            "entry": image_base + entry_rva, "image_base": image_base,
            "sections": sections, "symbols": symbols,
            "imports": imports, "exports": exports,
        }
    except (struct.error, IndexError, ValueError):
        return None


def _pe_rva_to_off(rva: int, sections: list[dict]) -> int | None:
    for s in sections:
        size = max(s["vsize"], s["rawsize"])
        if s["rva"] <= rva < s["rva"] + size:
            return rva - s["rva"] + s["rawptr"]
    return None


def _pe_imports(data: bytes, imp_rva: int, sections: list[dict], base: int) -> list[dict]:
    out: list[dict] = []
    if not imp_rva:
        return out
    off = _pe_rva_to_off(imp_rva, sections)
    if off is None:
        return out
    is64 = any(s for s in sections)  # thunk width decided per-arch below by caller? keep 32/64 agnostic
    for i in range(512):
        d = off + i * 20
        if d + 20 > len(data):
            break
        name_rva, first = struct.unpack_from("<I", data, d + 12)[0], struct.unpack_from("<I", data, d + 16)[0]
        oft = struct.unpack_from("<I", data, d)[0]
        if name_rva == 0 and first == 0:
            break
        noff = _pe_rva_to_off(name_rva, sections)
        if noff is None:
            continue
        lib = _cstr(data, noff, 64)
        # walk the thunk array for the function names
        thunk_rva = oft or first
        toff = _pe_rva_to_off(thunk_rva, sections)
        if toff is None:
            out.append({"lib": lib, "name": "*"})
            continue
        for j in range(2048):
            # try 64-bit thunks first, fall back to 32-bit
            for width, fmt, hi in ((8, "<Q", 1 << 63), (4, "<I", 1 << 31)):
                if toff + j * width + width > len(data):
                    thunk = 0
                    break
                thunk = struct.unpack_from(fmt, data, toff + j * width)[0]
                break
            if not thunk:
                break
            if thunk & hi:
                out.append({"lib": lib, "name": f"#{thunk & 0xFFFF}"})
            else:
                hnoff = _pe_rva_to_off(thunk & 0x7FFFFFFF, sections)
                if hnoff is not None:
                    fn = _cstr(data, hnoff + 2, 64)
                    if fn:
                        out.append({"lib": lib, "name": fn})
            if len(out) > 4000:
                return out
    return out


def _pe_exports(data: bytes, exp_rva: int, sections: list[dict], base: int) -> list[dict]:
    out: list[dict] = []
    if not exp_rva:
        return out
    off = _pe_rva_to_off(exp_rva, sections)
    if off is None:
        return out
    try:
        nnames = struct.unpack_from("<I", data, off + 24)[0]
        names_rva = struct.unpack_from("<I", data, off + 32)[0]
        funcs_rva = struct.unpack_from("<I", data, off + 28)[0]
        ords_rva = struct.unpack_from("<I", data, off + 36)[0]
        naddr = _pe_rva_to_off(names_rva, sections)
        faddr = _pe_rva_to_off(funcs_rva, sections)
        oaddr = _pe_rva_to_off(ords_rva, sections)
        if None in (naddr, faddr, oaddr):
            return out
        for i in range(min(nnames, 8192)):
            nrva = struct.unpack_from("<I", data, naddr + i * 4)[0]
            noff = _pe_rva_to_off(nrva, sections)
            if noff is None:
                continue
            name = _cstr(data, noff, 128)
            idx = struct.unpack_from("<H", data, oaddr + i * 2)[0]
            frva = struct.unpack_from("<I", data, faddr + idx * 4)[0]
            out.append({"addr": base + frva, "name": name})
    except (struct.error, IndexError):
        pass
    return out


# ===========================================================================
# ELF
# ===========================================================================
_ELF_MACHINES = {0x03: ("x86", 32), 0x3E: ("x64", 64), 0x28: ("arm", 32),
                 0xB7: ("arm64", 64), 0x08: ("mips", 32)}
_SHT = {0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA",
        5: "HASH", 6: "DYNAMIC", 7: "NOTE", 8: "NOBITS", 9: "REL",
        11: "DYNSYM", 14: "INIT_ARRAY", 15: "FINI_ARRAY"}


def parse_elf(data: bytes) -> dict | None:
    if data[:4] != b"\x7fELF" or len(data) < 0x40:
        return None
    try:
        is64 = data[4] == 2
        le = "<" if data[5] == 1 else ">"
        emachine = struct.unpack_from(le + "H", data, 0x12)[0]
        arch, bits = _ELF_MACHINES.get(emachine, ("?", 64 if is64 else 32))
        if is64:
            entry = struct.unpack_from(le + "Q", data, 0x18)[0]
            shoff = struct.unpack_from(le + "Q", data, 0x28)[0]
            shentsize, shnum, shstrndx = struct.unpack_from(le + "HHH", data, 0x3A)
        else:
            entry = struct.unpack_from(le + "I", data, 0x18)[0]
            shoff = struct.unpack_from(le + "I", data, 0x20)[0]
            shentsize, shnum, shstrndx = struct.unpack_from(le + "HHH", data, 0x30)

        # section headers
        raw_secs = []
        for i in range(min(shnum, 256)):
            b = shoff + i * shentsize
            if b + shentsize > len(data):
                break
            if is64:
                nameoff, stype, flags, addr, offset, size = struct.unpack_from(le + "IIQQQQ", data, b)
            else:
                nameoff, stype, flags, addr, offset, size = struct.unpack_from(le + "IIIIII", data, b)
            raw_secs.append({"nameoff": nameoff, "stype": stype, "flags": flags,
                             "addr": addr, "offset": offset, "size": size})
        # section-header string table
        shstr_off = raw_secs[shstrndx]["offset"] if shstrndx < len(raw_secs) else 0
        sections = []
        for s in raw_secs:
            name = _cstr(data, shstr_off + s["nameoff"], 64) if shstr_off else ""
            if not name and s["stype"] == 0:
                continue
            flags = s["flags"]
            perm = "r" + ("w" if flags & 0x1 else "-") + ("x" if flags & 0x4 else "-")
            raw = data[s["offset"]:s["offset"] + s["size"]] if s["stype"] != 8 else b""
            sections.append({
                "name": name or "(null)", "va": s["addr"], "rva": s["addr"],
                "vsize": s["size"], "rawptr": s["offset"], "rawsize": s["size"],
                "perm": perm, "type": _SHT.get(s["stype"], str(s["stype"])),
                "entropy": _entropy(raw),
            })

        symbols, exports, imports = _elf_symbols(data, raw_secs, is64, le)
        return {
            "format": "ELF", "arch": arch, "bits": bits,
            "entry": entry, "image_base": 0,
            "sections": sections, "symbols": symbols,
            "imports": imports, "exports": exports,
        }
    except (struct.error, IndexError, ValueError):
        return None


_STT = {0: "notype", 1: "data", 2: "function", 3: "section", 4: "file"}


def _elf_symbols(data, raw_secs, is64, le):
    symbols, exports, imports = [], [], []
    for sec in raw_secs:
        if sec["stype"] not in (2, 11):  # SYMTAB / DYNSYM
            continue
        link = None
        # the associated string table is in sh_link; re-read it
        # sh_link sits at a fixed offset we didn't store, so find the STRTAB
        # heuristically: the first STRTAB after this symtab, else any STRTAB.
        strtabs = [s for s in raw_secs if s["stype"] == 3]
        link = strtabs[-1] if strtabs else None
        entsize = 24 if is64 else 16
        n = sec["size"] // entsize if entsize else 0
        stroff = link["offset"] if link else 0
        for i in range(min(n, 20000)):
            b = sec["offset"] + i * entsize
            if b + entsize > len(data):
                break
            if is64:
                nameoff, info, other, shndx, value, size = struct.unpack_from(le + "IBBHQQ", data, b)
            else:
                nameoff, value, size, info, other, shndx = struct.unpack_from(le + "IIIBBH", data, b)
            stype = _STT.get(info & 0xF, str(info & 0xF))
            name = _cstr(data, stroff + nameoff, 128) if stroff else ""
            if not name:
                continue
            if value:
                symbols.append({"addr": value, "name": name, "type": stype})
                if stype == "function":
                    exports.append({"addr": value, "name": name})
            elif stype in ("function", "notype"):
                imports.append({"lib": "libc", "name": name})
    # de-dup symbols by (addr,name)
    seen, uniq = set(), []
    for s in symbols:
        k = (s["addr"], s["name"])
        if k not in seen:
            seen.add(k)
            uniq.append(s)
    return uniq, exports, imports


# ===========================================================================
# dispatch + address translation
# ===========================================================================
def parse(data: bytes) -> dict | None:
    return parse_pe(data) or parse_elf(data)


def va_to_off(binary: dict, va: int) -> int | None:
    for s in binary["sections"]:
        if s["rawsize"] and s["va"] <= va < s["va"] + max(s["vsize"], s["rawsize"]):
            return va - s["va"] + s["rawptr"]
    return None


def off_to_va(binary: dict, off: int) -> int | None:
    for s in binary["sections"]:
        if s["rawptr"] <= off < s["rawptr"] + s["rawsize"]:
            return off - s["rawptr"] + s["va"]
    return None


def code_sections(binary: dict) -> list[dict]:
    """Sections that hold executable code."""
    out = [s for s in binary["sections"] if "x" in s["perm"]]
    if out:
        return out
    # PE without perm flags parsed, or odd layouts: fall back by name/type.
    return [s for s in binary["sections"]
            if s["type"] == "CODE" or s["name"].lower() in (".text", "text", "__text")]
