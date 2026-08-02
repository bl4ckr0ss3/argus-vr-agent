"""Function discovery, cross-references and basic-block CFG.

Strategy (recursive-descent, symbol-seeded):
  1. Seed from the entry point + every code symbol/export.
  2. Follow direct call/jmp targets that land in an executable section.
  3. Each function ends at its first `ret`/terminal `jmp` past the entry, or a
     sane cap. Gaps are filled by a light linear sweep so stripped binaries
     still show something.

This is a heuristic (not a full recursive-traversal recompiler), but it's
enough to populate the function list, xrefs, and per-function CFG the UI wants.
"""
from __future__ import annotations

import re
import time

from . import container as C
from . import disasm as D

_MAX_FUNC_INSNS = 4000
_HEXOP = re.compile(r"^0x[0-9a-fA-F]+$")


# Bound worst-case work on huge / packed .text so load stays snappy.
_SWEEP_INSN_CAP = 1_500_000
_SWEEP_BUDGET_S = 3.5
_MAX_FUNCTIONS = 8000


def discover(binary: dict, data: bytes, md) -> dict:
    """Return {functions:[{addr,name,size}], xrefs:{addr:[from,...]}}.

    Fast path: ONE linear disassembly sweep of each code section collects every
    direct call/jmp target (function candidates + xrefs) in a single pass — far
    cheaper than recursively walking every function (which overlaps massively).
    Prologue detection + symbols fill in starts the sweep can't reach."""
    code = C.code_sections(binary)
    if not code or md is None:
        return {"functions": _symbol_functions(binary), "xrefs": {}}

    named = {s["addr"]: s["name"] for s in binary["symbols"]
             if s["type"] in ("function", "export") and s["addr"]}
    for e in binary.get("exports", []):
        named.setdefault(e["addr"], e["name"])
    if binary.get("entry"):
        named.setdefault(binary["entry"], "entry")

    func_addrs = set(named)
    if binary.get("entry"):
        func_addrs.add(binary["entry"])
    func_addrs |= _prologue_scan(binary, data, md)

    xrefs: dict[int, list[int]] = {}
    code_ranges = [(s["va"], s["va"] + max(s["vsize"], s["rawsize"])) for s in code]

    def in_code(va):
        return any(lo <= va < hi for lo, hi in code_ranges)

    # Fast, detail-off linear sweep. Direct call/jmp targets are read straight
    # from op_str text ("call 0x1400..") — no operand decoding needed.
    fast = D.make_fast_engine(binary["arch"], binary["bits"]) or md
    seen = 0
    deadline = time.monotonic() + _SWEEP_BUDGET_S
    for s in code:
        raw = data[s["rawptr"]:s["rawptr"] + s["rawsize"]]
        for ins in fast.disasm(raw, s["va"]):
            seen += 1
            if seen % 20000 == 0 and time.monotonic() > deadline:
                seen = _SWEEP_INSN_CAP + 1
                break
            if seen > _SWEEP_INSN_CAP:
                break
            mn = ins.mnemonic
            is_call = mn == "call"
            if not (is_call or (mn and mn[0] == "j")):
                continue
            ops = ins.op_str
            if not _HEXOP.match(ops):
                continue
            tgt = int(ops, 16)
            lst = xrefs.get(tgt)
            if lst is None:
                xrefs[tgt] = [ins.address]
            elif len(lst) < 64 and ins.address not in lst:
                lst.append(ins.address)
            if is_call and in_code(tgt):
                func_addrs.add(tgt)
        if seen > _SWEEP_INSN_CAP:
            break

    ordered = sorted(func_addrs)[:_MAX_FUNCTIONS]
    functions = []
    for i, addr in enumerate(ordered):
        nxt = ordered[i + 1] if i + 1 < len(ordered) else None
        size = min(nxt - addr, 0x4000) if nxt and nxt > addr else 0
        functions.append({
            "addr": addr,
            "name": named.get(addr) or f"FUN_{addr:08x}",
            "size": size,
        })
    return {"functions": functions, "xrefs": {str(k): v for k, v in xrefs.items()}}


# Common x86/x64 function prologues — a start almost always begins with one.
_PROLOGUES = (
    b"\x55\x48\x89\xe5",          # push rbp; mov rbp,rsp
    b"\x55\x8b\xec",              # push ebp; mov ebp,esp  (x86)
    b"\x48\x89\x5c\x24",          # mov [rsp+x],rbx
    b"\x48\x83\xec",              # sub rsp, imm8
    b"\x48\x81\xec",              # sub rsp, imm32
    b"\x40\x53",                  # push rbx (REX)
    b"\x40\x55",                  # push rbp (REX)
    b"\x53\x48\x83\xec",          # push rbx; sub rsp
    b"\x56\x57",                  # push rsi; push rdi
    b"\xf3\x0f\x1e\xfa",          # endbr64
)


def _prologue_scan(binary: dict, data: bytes, md, cap: int = 6000) -> set[int]:
    """Find likely function starts by scanning code sections for prologues that
    sit just after padding (int3/nop/ret). Bounded to keep load fast."""
    starts: set[int] = set()
    for s in C.code_sections(binary):
        raw = data[s["rawptr"]:s["rawptr"] + s["rawsize"]]
        base = s["va"]
        i = 0
        n = len(raw)
        while i < n and len(starts) < cap:
            # a start is a prologue preceded by padding or section start
            prev = raw[i - 1] if i > 0 else 0xCC
            if prev in (0xCC, 0x90) or i == 0:
                for pro in _PROLOGUES:
                    if raw[i:i + len(pro)] == pro:
                        starts.add(base + i)
                        break
            i += 1
    return starts


def _symbol_functions(binary: dict) -> list[dict]:
    out = []
    for s in binary["symbols"]:
        if s["type"] in ("function", "export") and s["addr"]:
            out.append({"addr": s["addr"], "name": s["name"], "size": 0})
    if binary.get("entry"):
        out.append({"addr": binary["entry"], "name": "entry", "size": 0})
    seen, uniq = set(), []
    for f in sorted(out, key=lambda x: x["addr"]):
        if f["addr"] in seen:
            continue
        seen.add(f["addr"])
        uniq.append(f)
    return uniq


def _in_code(binary: dict, va: int) -> bool:
    for s in C.code_sections(binary):
        if s["va"] <= va < s["va"] + max(s["vsize"], s["rawsize"]):
            return True
    return False


def _walk(binary, data, md, addr, cap=_MAX_FUNC_INSNS):
    """Disassemble a function's instruction stream until a terminal ret/jmp."""
    off = C.va_to_off(binary, addr)
    if off is None:
        return []
    rows = D.disassemble(data, off, addr, cap, md)
    out = []
    for r in rows:
        out.append(r)
        if r["flow"] == "ret":
            break
        if r["flow"] == "jmp" and r["target"] is None:
            break
    return out


def function_disasm(binary, data, md, addr) -> list[dict]:
    """Full disassembly rows for one function, resolving branch labels."""
    rows = _walk(binary, data, md, addr)
    # attach human labels for import thunks / known symbols on targets
    sym = {s["addr"]: s["name"] for s in binary["symbols"] if s["addr"]}
    for f in binary.get("exports", []):
        sym.setdefault(f["addr"], f["name"])
    for r in rows:
        t = r.get("target")
        if t is not None and t in sym:
            r["label"] = sym[t]
    return rows


def basic_blocks(rows: list[dict]) -> list[dict]:
    """Split a function's rows into basic blocks for the CFG view."""
    if not rows:
        return []
    leaders = {rows[0]["addr"]}
    addrs = {r["addr"] for r in rows}
    for r in rows:
        if r["flow"] in ("jmp", "cjmp", "call") and r["target"] in addrs:
            leaders.add(r["target"])
        if r["flow"] in ("cjmp", "jmp", "ret"):
            nxt = r["addr"] + r["size"]
            if nxt in addrs:
                leaders.add(nxt)
    blocks, cur = [], None
    for r in rows:
        if r["addr"] in leaders:
            if cur:
                blocks.append(cur)
            cur = {"start": r["addr"], "rows": [], "succ": []}
        if cur is None:
            cur = {"start": r["addr"], "rows": [], "succ": []}
        cur["rows"].append(r)
        if r["flow"] == "cjmp":
            cur["succ"] = [t for t in (r["target"], r["addr"] + r["size"]) if t]
        elif r["flow"] == "jmp":
            cur["succ"] = [r["target"]] if r["target"] else []
        elif r["flow"] == "ret":
            cur["succ"] = []
    if cur:
        blocks.append(cur)
    return blocks
