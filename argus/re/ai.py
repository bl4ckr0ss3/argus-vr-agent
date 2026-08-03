"""AI assist for the Reverser — LLM-powered decompilation + Q&A over a
function's disassembly. Host-side only (the LLM key must never be in the
detonation VM). Uses ARGUS's configured backend (DeepSeek / OpenRouter / etc.).

Degrades cleanly: if no LLM is configured, the endpoints return an error and
the rule-based decompiler still works.
"""
from __future__ import annotations

import os

from . import functions as F

_CAP = 240  # instructions of context sent to the model — bounds token cost


def _backend():
    """Reverser AI backend. Decompile/ask need LONG output, so a heavy REASONING
    model (deepseek-v4-flash/pro) is wrong — it spends the whole token budget
    thinking and never writes the code. Prefer a non-reasoning model
    (deepseek-chat); override with ARGUS_RE_MODEL."""
    from ..llm import make_backend
    import config
    cfg = dict(config.resolve_llm())
    ov = os.environ.get("ARGUS_RE_MODEL", "").strip()
    if ov:
        cfg["model"] = ov
    elif cfg.get("provider") == "deepseek":
        cfg["model"] = "deepseek-chat"
    return make_backend(cfg)


def _ready() -> bool:
    try:
        return bool(getattr(_backend(), "ready", False))
    except Exception:
        return False


def _fmt(sess, addr) -> tuple[str, str]:
    rows = F.function_disasm(sess.binary, sess.data, sess.md, addr)
    name = next((f["name"] for f in sess.functions if f["addr"] == addr), f"FUN_{addr:08x}")
    if not rows:
        return name, ""
    sym = {s["addr"]: s["name"] for s in sess.symbols() if s.get("addr")}
    lines = []
    for r in rows[:_CAP]:
        tgt = r.get("target")
        note = f"  ; -> {sym.get(tgt)}" if (tgt in sym) else ""
        lines.append(f"{r['addr']:#010x}  {r['mnemonic']} {r['operands']}{note}".rstrip())
    return name, "\n".join(lines)


def ai_decompile(sess, addr: int) -> dict:
    if not sess.binary or sess.md is None:
        return {"error": "no disassembler"}
    if not _ready():
        return {"error": "no LLM configured — set an LLM key on the host (e.g. DEEPSEEK_API_KEY)"}
    name, disasm = _fmt(sess, addr)
    if not disasm:
        return {"error": "no disassembly for this function"}
    arch = sess.binary["arch"]
    prompt = (
        f"You are an expert reverse engineer. Below is the {arch} disassembly of a "
        f"function `{name}`. Reconstruct clean, readable pseudo-C for it (types, "
        f"named locals, control flow), then after a line containing only `// ---` "
        f"add a 1-2 sentence explanation of what the function does. Output ONLY the "
        f"pseudo-C and the explanation, no markdown fences, no preamble.\n\n"
        f"Disassembly:\n{disasm}\n"
    )
    try:
        out = (_backend().complete(prompt, max_tokens=6000) or "").strip()
    except TypeError:
        out = (_backend().complete(prompt) or "").strip()
    except Exception as e:
        return {"error": f"LLM error: {e}"}
    code, _, expl = out.partition("// ---")
    return {"addr": addr, "name": name, "engine": _backend().model,
            "text": out, "code": code.strip(), "explanation": expl.strip()}


def ai_ask(sess, addr: int, question: str) -> dict:
    if not _ready():
        return {"error": "no LLM configured — set an LLM key on the host"}
    q = (question or "").strip()
    if not q:
        return {"error": "empty question"}
    name, disasm = _fmt(sess, addr) if (sess.binary and sess.md and addr) else ("", "")
    ctx = f"\n\nContext — disassembly of `{name}`:\n{disasm}\n" if disasm else ""
    prompt = (
        "You are an expert reverse engineer and malware analyst. Answer the "
        "question concisely and technically; cite instruction addresses when "
        "relevant. If the disassembly doesn't support an answer, say so.\n"
        f"Question: {q}{ctx}"
    )
    try:
        out = (_backend().complete(prompt, max_tokens=4000) or "").strip()
    except TypeError:
        out = (_backend().complete(prompt) or "").strip()
    except Exception as e:
        return {"error": f"LLM error: {e}"}
    return {"addr": addr, "question": q, "answer": out, "engine": _backend().model}
