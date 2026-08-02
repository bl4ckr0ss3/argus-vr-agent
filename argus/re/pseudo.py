"""Rule-based pseudocode — a free, offline, no-API 'decompiler'.

This is NOT a real decompiler (no data-flow recovery / type inference like
Ghidra). It lifts the disassembly into readable, Ghidra-flavoured pseudo-C:
call sites become function calls, cmp+jcc become `if`, jump targets become
LAB_ labels, ret becomes `return`. It's meant to make a function *readable*
at a glance and to be a stable base a real backend (local Ollama, or Ghidra
headless) can later replace — the UI contract is identical.

Every emitted line carries the source instruction address so the UI can show
`addr:` citations and highlight the matching disassembly line.
"""
from __future__ import annotations

import re

# WinAPI / libc semantics so calls read meaningfully instead of FUN_xxxx.
_KNOWN = {
    "getopt_long": "getopt_long", "setlocale": "setlocale",
    "bindtextdomain": "bindtextdomain", "textdomain": "textdomain",
    "malloc": "malloc", "free": "free", "memcpy": "memcpy", "memset": "memset",
    "strlen": "strlen", "strcmp": "strcmp", "strcpy": "strcpy", "printf": "printf",
    "CreateFileA": "CreateFileA", "CreateFileW": "CreateFileW",
    "VirtualAlloc": "VirtualAlloc", "WriteProcessMemory": "WriteProcessMemory",
    "CreateProcessA": "CreateProcessA", "RegSetValueExA": "RegSetValueExA",
    "LoadLibraryA": "LoadLibraryA", "GetProcAddress": "GetProcAddress",
    "WinExec": "WinExec", "ShellExecuteA": "ShellExecuteA",
    "InternetOpenA": "InternetOpenA", "URLDownloadToFileA": "URLDownloadToFileA",
}

_CJMP = {
    "je": "==", "jz": "==", "jne": "!=", "jnz": "!=",
    "jg": ">", "jge": ">=", "jl": "<", "jle": "<=",
    "ja": ">", "jae": ">=", "jb": "<", "jbe": "<=",
    "js": "< 0", "jns": ">= 0",
}


def _var(reg: str) -> str:
    """Map a register to a stable pseudo-variable name."""
    r = reg.strip().lower()
    base = {
        "rax": "ret", "eax": "ret", "rdi": "param_1", "edi": "param_1",
        "rsi": "param_2", "esi": "param_2", "rdx": "param_3", "edx": "param_3",
        "rcx": "param_4", "ecx": "param_4", "r8": "param_5", "r9": "param_6",
    }
    return base.get(r, "u" + r.capitalize())


def decompile(rows: list[dict], func_name: str, arch: str) -> dict:
    """Return {lines:[{addr, text, indent}], text} for a function's rows."""
    if not rows:
        return {"lines": [], "text": ""}

    # jump targets that fall inside this function -> LAB_ labels
    addrs = {r["addr"] for r in rows}
    labels = {}
    for r in rows:
        t = r.get("target")
        if r["flow"] in ("jmp", "cjmp") and t in addrs:
            labels[t] = f"LAB_{t:08x}"

    lines: list[dict] = []
    indent = 1

    def emit(addr, text, ind=None):
        lines.append({"addr": addr, "text": text, "indent": ind if ind is not None else indent})

    sig = f"undefined8 {func_name}(void)" if func_name and not func_name.startswith("FUN_") \
        else f"void {func_name}(void)"
    lines.append({"addr": rows[0]["addr"], "text": sig, "indent": 0})
    lines.append({"addr": rows[0]["addr"], "text": "{", "indent": 0})

    last_cmp = None
    for r in rows:
        a, mn, ops = r["addr"], r["mnemonic"], r["operands"]
        if a in labels:
            emit(a, f'{labels[a]}:', ind=0)

        if mn == "mov" or mn == "lea":
            dst, _, src = ops.partition(",")
            if dst and src:
                emit(a, f"{_var(dst)} = {_clean(src)};")
        elif mn in ("push", "pop", "nop", "endbr64", "endbr32"):
            continue
        elif mn == "call":
            name = r.get("label") or _clean(ops)
            fn = _KNOWN.get(name, name)
            emit(a, f"ret = {fn}();")
        elif mn == "cmp" or mn == "test":
            last_cmp = tuple(x.strip() for x in ops.split(",")[:2])
        elif mn in _CJMP:
            op = _CJMP[mn]
            tgt = labels.get(r.get("target"), _clean(ops))
            if last_cmp and len(last_cmp) == 2:
                cond = f"{_clean(last_cmp[0])} {op} {_clean(last_cmp[1])}"
            else:
                cond = f"{_clean(ops)} {op} 0" if op.endswith("0") else _clean(ops)
            emit(a, f"if ({cond}) goto {tgt};")
            last_cmp = None
        elif mn == "jmp":
            tgt = labels.get(r.get("target"))
            if tgt:
                emit(a, f"goto {tgt};")
            else:
                emit(a, f"/* tail-call {_clean(ops)} */")
        elif mn.startswith("ret"):
            emit(a, "return ret;")
        elif mn in ("add", "sub", "and", "or", "xor", "shl", "shr", "imul", "mul"):
            dst, _, src = ops.partition(",")
            symb = {"add": "+", "sub": "-", "and": "&", "or": "|", "xor": "^",
                    "shl": "<<", "shr": ">>", "imul": "*", "mul": "*"}[mn]
            if dst and src:
                if mn == "xor" and _clean(dst) == _clean(src):
                    emit(a, f"{_var(dst)} = 0;")
                else:
                    emit(a, f"{_var(dst)} = {_var(dst)} {symb} {_clean(src)};")
        else:
            emit(a, f"/* {mn} {ops} */")

    lines.append({"addr": rows[-1]["addr"], "text": "}", "indent": 0})
    text = "\n".join(("  " * ln["indent"]) + ln["text"] for ln in lines)
    return {"lines": lines, "text": text}


_HEXRE = re.compile(r"\b0x[0-9a-fA-F]+\b")


def _clean(operand: str) -> str:
    """Tidy an operand into something C-ish. Registers become pseudo-vars,
    memory refs become DAT_/*(...) forms, immediates stay hex."""
    o = operand.strip()
    if not o:
        return "0"
    # memory dereference [ ... ]
    m = re.match(r"(?:\w+ ptr )?\[([^\]]+)\]", o)
    if m:
        inner = m.group(1)
        hexm = _HEXRE.search(inner)
        if hexm and "+" not in inner and "*" not in inner:
            return f"DAT_{int(hexm.group(0), 16):08x}"
        return f"*(undefined *)({_reg_subst(inner)})"
    if re.fullmatch(r"[a-z][a-z0-9]{1,3}", o):
        return _var(o)
    return _reg_subst(o)


_REGS = ("rax", "eax", "rbx", "ebx", "rcx", "ecx", "rdx", "edx",
         "rsi", "esi", "rdi", "edi", "rbp", "rsp", "r8", "r9", "r10",
         "r11", "r12", "r13", "r14", "r15")


def _reg_subst(s: str) -> str:
    def repl(m):
        return _var(m.group(0))
    return re.sub(r"\b(" + "|".join(_REGS) + r")\b", repl, s)
