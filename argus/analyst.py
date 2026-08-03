"""Optional AI analyst — turns a finding's structured telemetry into a short,
expert threat-intel narrative via the configured LLM (OpenRouter/DeepSeek/etc.).

OFF by default. Enable with ARGUS_ANALYST=1 and an LLM key on the HOST (never in
the detonation VM — this runs host-side at publish time). Degrades to None on
any error or when no LLM is configured, so publishing never depends on it.
"""
from __future__ import annotations

import json
import os

_MAX = 480  # keep the summary tight — it rides inside VT comments + report cards


def enabled() -> bool:
    return os.environ.get("ARGUS_ANALYST", "").strip() == "1"


def _facts(struct: dict) -> dict:
    """Compact, de-noised facts for the prompt (no giant paths)."""
    def short(seq, n=6):
        out = []
        for x in (seq or [])[:n]:
            s = str(x)
            out.append(s if len(s) <= 90 else s[:87] + "...")
        return out
    pk = struct.get("packer")
    if isinstance(pk, dict):
        pk = pk.get("packer")
    return {
        "family": struct.get("family"),
        "verdict": struct.get("verdict"),
        "confidence": struct.get("confidence"),
        "file": struct.get("sample"),
        "signals": struct.get("signals") or [],
        "attack": [f"{t.get('id')} {t.get('name','')}".strip() for t in (struct.get("attack") or [])][:8],
        "child_processes": short(struct.get("spawned")),
        "dropped": short(struct.get("staged_payloads")),
        "network": short(struct.get("net")),
        "packing": pk if struct.get("packed") else None,
        "yara": (struct.get("yara") or [])[:6],
    }


_PROMPT = (
    "You are a senior malware analyst writing for a public threat-intel report. "
    "Given the automated dynamic-analysis telemetry below, write 2-4 sentences of "
    "concise, technical analysis: what the sample most likely IS (family/type and "
    "its goal), the notable behaviour, and the attack chain. Be specific and "
    "confident where the evidence supports it; hedge only where it doesn't. Plain "
    "prose, no bullet points, no preamble, no disclaimers, no markdown. Telemetry:\n"
)


def summarize(struct: dict) -> str | None:
    """Return a short expert analysis of the finding, or None if unavailable."""
    if not enabled():
        return None
    try:
        from .llm import make_backend
        b = make_backend()
        if not getattr(b, "ready", False):
            return None
        out = b.complete(_PROMPT + json.dumps(_facts(struct), separators=(",", ":")))
        out = (out or "").strip().strip('"')
        if "only reasoning" in out.lower():   # reasoning model ran out of budget
            return None
        # collapse whitespace/newlines to a single tidy paragraph
        out = " ".join(out.split())
        return out[:_MAX] or None
    except Exception:
        return None
