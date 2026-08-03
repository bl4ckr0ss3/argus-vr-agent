"""Disassembly (capstone) and assembly (keystone) wrappers.

Both are OPTIONAL. If capstone/keystone aren't installed the panel still loads
(sections, symbols, hex, strings, imports/exports work) and the disassembly /
assembler views report that the library is missing with an install hint.
"""
from __future__ import annotations

try:
    import capstone  # type: ignore
    HAVE_CAPSTONE = True
except Exception:  # pragma: no cover - env dependent
    capstone = None
    HAVE_CAPSTONE = False

try:
    import keystone  # type: ignore
    HAVE_KEYSTONE = True
except Exception:  # pragma: no cover
    keystone = None
    HAVE_KEYSTONE = False


def _cs_mode(arch: str, bits: int):
    if not HAVE_CAPSTONE:
        return None
    if arch in ("x86", "x64"):
        return capstone.CS_ARCH_X86, (capstone.CS_MODE_64 if bits == 64 else capstone.CS_MODE_32)
    if arch == "arm64":
        return capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM
    if arch == "arm":
        return capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM
    return None


def make_engine(arch: str, bits: int):
    spec = _cs_mode(arch, bits)
    if not spec:
        return None
    md = capstone.Cs(*spec)
    md.detail = True
    md.skipdata = True
    return md


def make_fast_engine(arch: str, bits: int):
    """A detail-OFF engine for the linear discovery sweep — capstone is several
    times faster without per-instruction group/operand decoding. Targets are
    parsed from op_str text instead."""
    spec = _cs_mode(arch, bits)
    if not spec:
        return None
    md = capstone.Cs(*spec)
    md.detail = False
    md.skipdata = True
    return md


def disassemble(data: bytes, off: int, va: int, count: int, md) -> list[dict]:
    """Disassemble up to `count` instructions from file offset `off` (which maps
    to virtual address `va`). Returns rows the UI renders directly."""
    if md is None:
        return []
    out = []
    for insn in md.disasm(data[off:off + count * 16 + 16], va):
        out.append({
            "addr": insn.address,
            "bytes": insn.bytes.hex(),
            "mnemonic": insn.mnemonic,
            "operands": insn.op_str,
            "size": insn.size,
            "flow": _flow(insn),
            "target": _branch_target(insn),
        })
        if len(out) >= count:
            break
    return out


def _flow(insn) -> str:
    """Classify control flow for CFG/coloring: call / jmp / cjmp / ret / normal.

    `insn.groups` is read INSIDE the try — a SKIPDATA '.byte' pseudo-instruction
    (undecodable bytes) raises CsError(CS_ERR_SKIPDATA) on any detail access."""
    if not HAVE_CAPSTONE:
        return "normal"
    try:
        g = insn.groups
        if capstone.CS_GRP_CALL in g:
            return "call"
        if capstone.CS_GRP_RET in g:
            return "ret"
        if capstone.CS_GRP_JUMP in g:
            return "jmp" if insn.mnemonic == "jmp" else "cjmp"
    except Exception:
        pass
    return "normal"


def _branch_target(insn) -> int | None:
    """Immediate call/jmp target, if the operand is a direct address.

    Handles x86 (X86_OP_IMM) and ARM/ARM64 (ARM_OP_IMM / ARM64_OP_IMM) — the old
    code only checked x86, so cross-references for ARM binaries were never found.
    """
    if not HAVE_CAPSTONE:
        return None
    try:
        if capstone.CS_GRP_JUMP not in insn.groups and capstone.CS_GRP_CALL not in insn.groups:
            return None
        if getattr(capstone, "x86", None) is not None:
            for op in insn.operands:
                if op.type == capstone.x86.X86_OP_IMM:
                    return op.imm
        if getattr(capstone, "arm", None) is not None:
            for op in insn.operands:
                if (op.type == getattr(capstone.arm, "ARM_OP_IMM", -1)):
                    return op.imm
        if getattr(capstone, "arm64", None) is not None:
            for op in insn.operands:
                if (op.type == getattr(capstone.arm64, "ARM64_OP_IMM", -1)):
                    return op.imm
    except Exception:
        return None
    return None


def assemble(code: str, arch: str, bits: int, addr: int = 0) -> dict:
    """Assemble asm text -> machine bytes. Returns {ok, hex, bytes, count, error}."""
    if not HAVE_KEYSTONE:
        return {"ok": False, "error": "keystone not installed — pip install keystone-engine"}
    ksarch, ksmode = None, None
    if arch in ("x86", "x64"):
        ksarch = keystone.KS_ARCH_X86
        ksmode = keystone.KS_MODE_64 if bits == 64 else keystone.KS_MODE_32
    elif arch == "arm64":
        ksarch, ksmode = keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN
    elif arch == "arm":
        ksarch, ksmode = keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM
    else:
        return {"ok": False, "error": f"unsupported arch: {arch}"}
    try:
        ks = keystone.Ks(ksarch, ksmode)
        encoding, count = ks.asm(code, addr)
        if encoding is None:
            return {"ok": False, "error": "nothing assembled"}
        b = bytes(encoding)
        return {"ok": True, "hex": b.hex(), "bytes": " ".join(f"{x:02x}" for x in b),
                "count": count, "len": len(b)}
    except Exception as e:  # keystone.KsError and friends
        return {"ok": False, "error": str(e)}
