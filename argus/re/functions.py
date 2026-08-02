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

from . import container as C
from . import disasm as D

_MAX_FUNC_INSNS = 4000


def discover(binary: dict, data: bytes, md) -> dict:
    """Return {functions:[{addr,name,size}], xrefs:{addr:[from,...]}}."""
    code = C.code_sections(binary)
    if not code or md is None:
        # No disassembler: still surface symbol-based functions so the list works.
        return {"functions": _symbol_functions(binary), "xrefs": {}}

    named = {s["addr"]: s["name"] for s in binary["symbols"]
             if s["type"] in ("function", "export") and s["addr"]}
    for e in binary.get("exports", []):
        named.setdefault(e["addr"], e["name"])
    if binary.get("entry"):
        named.setdefault(binary["entry"], "entry")

    seeds = set(named)
    if binary.get("entry"):
        seeds.add(binary["entry"])
    # Stripped binaries (most malware) have almost no named functions. Seed the
    # sweep with prologue-detected starts so the function list is actually rich.
    seeds |= _prologue_scan(binary, data, md)

    xrefs: dict[int, list[int]] = {}
    func_addrs = set(seeds)
    # follow direct branches to find more function starts (calls only -> starts)
    visited_scan = set()
    worklist = list(seeds)
    while worklist:
        fa = worklist.pop()
        if fa in visited_scan:
            continue
        visited_scan.add(fa)
        for ins in _walk(binary, data, md, fa):
            tgt = ins.get("target")
            if tgt is None:
                continue
            xrefs.setdefault(tgt, [])
            if ins["addr"] not in xrefs[tgt]:
                xrefs[tgt].append(ins["addr"])
            if ins["flow"] == "call" and _in_code(binary, tgt):
                if tgt not in func_addrs:
                    func_addrs.add(tgt)
                    worklist.append(tgt)

    functions = []
    ordered = sorted(func_addrs)
    for i, addr in enumerate(ordered):
        end = ordered[i + 1] if i + 1 < len(ordered) else None
        size = _func_size(binary, data, md, addr, end)
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


def _func_size(binary, data, md, addr, hard_end):
    off = C.va_to_off(binary, addr)
    if off is None:
        return 0
    rows = _walk(binary, data, md, addr)
    if not rows:
        return 0
    last = rows[-1]
    end = last["addr"] + last["size"]
    if hard_end and end > hard_end:
        end = hard_end
    return max(0, end - addr)


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
