"""ARGUS progression — the hunter level-up system.

A light gamification layer that turns confirmed bug-hunting into measurable
progress. Every time the agent records a candidate (see argus/tools/findings.py)
this engine awards XP, tracks the bug in a persistent ledger, unlocks
achievements, and levels the operator up through named ranks.

Design goals:
  - Zero dependencies (pure stdlib) and portable, like the rest of ARGUS.
  - Fair: XP is keyed to a bug *fingerprint*, so re-logging the same lead does
    not farm XP — only genuine progress (a newly-passed verification gate) pays
    out the delta. Fully proving a bug (all four gates) is the jackpot.
  - Durable: state is a single JSON file, written atomically, tolerant of a
    missing/corrupt file (it just starts fresh).
  - Thread-safe: the web server touches this from multiple request threads.

The panel in the web console reads snapshot() to render the HUD + ledger.
"""
from __future__ import annotations

import json
import os
import re
import threading
from datetime import datetime, timezone

import config

_LOCK = threading.RLock()
_SLUG_RE = re.compile(r"[^a-z0-9]+")

# --- XP economy ------------------------------------------------------------
XP_NEW_CANDIDATE = 25          # logging a brand-new lead
XP_PER_GATE = 20               # each verification gate genuinely passed
XP_FULL_VERIFY_BONUS = 120     # all four gates -> a real, reproduced finding
GATES = ("root_cause", "reproduced", "impact", "scope")

# Rank tiers: (min_level, name, color). The operator's rank is the highest
# tier whose min_level they have reached.
RANKS = [
    (1,  "INITIATE",        "#8b9bb4"),
    (5,  "RECON",           "#38bdf8"),
    (10, "OPERATOR",        "#34d399"),
    (20, "BREAKER",         "#fbbf24"),
    (35, "EXPLOITER",       "#fb923c"),
    (55, "ZERO-DAY HUNTER", "#f43f5e"),
    (80, "APEX GHOST",      "#c084fc"),
]

# Achievements: id -> (name, description, icon, xp bonus, predicate(stats)).
# `stats` is the derived dict from _stats(). Each unlocks once.
ACHIEVEMENTS = [
    ("first_blood",   "First Blood",     "First candidate logged.",                 "🩸", 50,
     lambda s: s["candidates"] >= 1),
    ("confirmed_kill", "Confirmed Kill", "First bug proven through all four gates.", "🎯", 200,
     lambda s: s["verified"] >= 1),
    ("double_tap",    "Double Tap",      "Two confirmed bugs.",                      "⚡", 150,
     lambda s: s["verified"] >= 2),
    ("hat_trick",     "Hat Trick",       "Three confirmed bugs.",                    "🔱", 250,
     lambda s: s["verified"] >= 3),
    ("polymath",      "Polymath",        "Bugs across five distinct CWE classes.",   "🧬", 300,
     lambda s: s["distinct_cwe"] >= 5),
    ("relentless",    "Relentless",      "Twenty-five candidates logged.",           "🐺", 200,
     lambda s: s["candidates"] >= 25),
    ("untouchable",   "Untouchable",     "Reached Breaker rank (Lv 20).",            "👁", 0,
     lambda s: s["level"] >= 20),
    ("apex_predator", "Apex Predator",   "Reached Zero-Day Hunter rank (Lv 55).",    "☠", 0,
     lambda s: s["level"] >= 55),
]

_MAX_EVENTS = 60


def _slug(text: str) -> str:
    return _SLUG_RE.sub("-", (text or "").lower()).strip("-")[:60] or "unknown"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --- level curve -----------------------------------------------------------
def _req(level: int) -> int:
    """XP required to advance FROM `level` to `level`+1. Grows super-linearly."""
    return int(round(80 * (level ** 1.35)))


def level_for_xp(xp_total: int) -> tuple[int, int, int]:
    """Return (level, xp_into_current_level, xp_needed_for_next_level)."""
    level, spent = 1, 0
    while True:
        need = _req(level)
        if xp_total < spent + need:
            return level, xp_total - spent, need
        spent += need
        level += 1
        if level > 999:  # hard stop, purely defensive
            return level, 0, _req(level)


def rank_for_level(level: int) -> dict:
    cur = RANKS[0]
    nxt = None
    for i, tier in enumerate(RANKS):
        if level >= tier[0]:
            cur = tier
            nxt = RANKS[i + 1] if i + 1 < len(RANKS) else None
    return {
        "name": cur[1], "color": cur[2], "min_level": cur[0],
        "next": ({"name": nxt[1], "min_level": nxt[0], "color": nxt[2]} if nxt else None),
    }


# --- persistence -----------------------------------------------------------
def _default_state() -> dict:
    return {"version": 1, "xp_total": 0, "records": 0,
            "bugs": {}, "achievements": [], "events": []}


def _load() -> dict:
    path = config.PROGRESSION_FILE
    if not path.exists():
        return _default_state()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        # merge onto defaults so older/partial files still load
        base = _default_state()
        base.update({k: data.get(k, base[k]) for k in base})
        return base
    except Exception:
        return _default_state()


def _save(state: dict) -> None:
    path = config.PROGRESSION_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
    os.replace(tmp, path)  # atomic


# --- derived stats ---------------------------------------------------------
def _stats(state: dict) -> dict:
    bugs = state["bugs"].values()
    verified = sum(1 for b in bugs if b.get("verified"))
    cwes = {(_slug(b.get("cwe") or "")) for b in bugs if (b.get("cwe") or "").strip()}
    level, into, need = level_for_xp(state["xp_total"])
    return {
        "level": level, "xp_into_level": into, "xp_for_next": need,
        "candidates": len(state["bugs"]), "verified": verified,
        "distinct_cwe": len(cwes), "records": state.get("records", 0),
    }


def _severity_weight(meta: dict) -> float:
    """A modest multiplier for high-impact classes (RCE / SYSTEM / kernel)."""
    blob = " ".join(str(meta.get(k, "")) for k in ("cwe", "title", "hypothesis")).lower()
    if any(w in blob for w in ("rce", "remote code", "kernel", "system", "ring0", "ring 0")):
        return 1.5
    if any(w in blob for w in ("privilege", "lpe", "eop", "arbitrary write", "arbitrary read")):
        return 1.25
    return 1.0


def _bug_value(gates: set[str], weight: float) -> int:
    """Total XP a bug is worth given its passed gates (idempotent)."""
    passed = [g for g in GATES if g in gates]
    xp = XP_NEW_CANDIDATE + XP_PER_GATE * len(passed)
    if len(passed) == len(GATES):
        xp += XP_FULL_VERIFY_BONUS
    return int(round(xp * weight))


def _check_achievements(state: dict) -> list[dict]:
    """Unlock any newly-earned achievements; return the new ones (with bonus applied)."""
    unlocked = set(state["achievements"])
    newly: list[dict] = []
    changed = True
    while changed:  # a bonus can push level up and unlock a level-gated badge
        changed = False
        stats = _stats(state)
        for aid, name, desc, icon, bonus, pred in ACHIEVEMENTS:
            if aid in unlocked:
                continue
            if pred(stats):
                unlocked.add(aid)
                state["achievements"].append(aid)
                state["xp_total"] += bonus
                newly.append({"id": aid, "name": name, "desc": desc, "icon": icon, "xp": bonus})
                changed = True
    return newly


# --- public API ------------------------------------------------------------
def award_for_candidate(meta: dict) -> dict:
    """Record a candidate against the progression state and return the outcome.

    meta keys used: title, target, cwe, hypothesis, gates_passed (list), verified (bool).
    Returns a dict describing XP gained, level change, and any new achievements —
    used both to give the model feedback in the tool result and to feed the panel.
    """
    title = (meta.get("title") or "").strip() or "untitled"
    target = (meta.get("target") or "unknown").strip()
    cwe = (meta.get("cwe") or "").strip()
    gates = meta.get("gates_passed") or []
    if isinstance(gates, str):
        gates = [gates]
    gate_set = {str(g).strip().lower() for g in gates} & set(GATES)
    verified = bool(meta.get("verified")) or gate_set.issuperset(GATES)
    weight = _severity_weight(meta)
    fp = f"{_slug(target)}::{_slug(title)}"

    with _LOCK:
        state = _load()
        state["records"] = state.get("records", 0) + 1
        stats_before = _stats(state)
        level_before = stats_before["level"]

        existing = state["bugs"].get(fp)
        prior_xp = existing["xp"] if existing else 0
        new_value = _bug_value(gate_set, weight)
        # only the positive delta pays out — passing a new gate on a known bug
        # is rewarded; re-logging the same lead is not.
        gain = max(0, new_value - prior_xp)
        is_new = existing is None

        merged_gates = sorted(set((existing or {}).get("gates", [])) | gate_set)
        state["bugs"][fp] = {
            "fingerprint": fp, "title": title, "target": target, "cwe": cwe,
            "gates": merged_gates, "verified": verified or bool((existing or {}).get("verified")),
            "xp": max(new_value, prior_xp), "severity_weight": weight,
            "first_seen": (existing or {}).get("first_seen") or _now(),
            "last_seen": _now(),
        }
        state["xp_total"] += gain

        new_ach = _check_achievements(state)
        stats_after = _stats(state)
        level_after = stats_after["level"]
        rank = rank_for_level(level_after)

        # activity feed entry
        verb = "PROVED" if state["bugs"][fp]["verified"] else ("LOGGED" if is_new else "ADVANCED")
        ev = {"ts": _now(), "kind": "bug", "verb": verb, "title": title,
              "target": target, "xp": gain,
              "gates": len(merged_gates), "verified": state["bugs"][fp]["verified"]}
        state["events"].insert(0, ev)
        for a in new_ach:
            state["events"].insert(0, {"ts": _now(), "kind": "achievement",
                                       "title": a["name"], "icon": a["icon"], "xp": a["xp"]})
        state["events"] = state["events"][:_MAX_EVENTS]
        _save(state)

    return {
        "xp_gained": gain, "total_xp": state["xp_total"],
        "level": level_after, "level_before": level_before,
        "leveled_up": level_after > level_before,
        "rank": rank["name"], "rank_color": rank["color"],
        "verified": state["bugs"][fp]["verified"], "bug_new": is_new,
        "gates_passed": len(merged_gates),
        "new_achievements": new_ach,
        "xp_into_level": stats_after["xp_into_level"],
        "xp_for_next": stats_after["xp_for_next"],
    }


def feedback_line(res: dict) -> str:
    """One-line, model-facing summary of an award (appended to tool output)."""
    bits = [f"+{res['xp_gained']} XP"]
    bits.append(f"Lv {res['level']} {res['rank']}")
    bits.append(f"{res['xp_into_level']}/{res['xp_for_next']} to next")
    line = "🎖  PROGRESSION · " + " · ".join(bits)
    if res["leveled_up"]:
        line += f"  ⏫ LEVEL UP! → {res['level']}"
    for a in res["new_achievements"]:
        line += f"\n🏅 ACHIEVEMENT UNLOCKED · {a['icon']} {a['name']} (+{a['xp']} XP) — {a['desc']}"
    return line


# Map a collab/debate verdict onto verification gates. A debate CONFIRMED means
# the analysis stands up to an adversarial reviewer — that's root-cause + scope,
# NOT a reproduced PoC (gates 2/3 still need a real trigger), so we never mark it
# fully verified from a debate alone. Keeps the zero-false-positive bar intact.
_VERDICT_GATES = {
    "confirmed": ["root_cause", "scope"],
    "needs more work": ["root_cause"],
    "needs_more_work": ["root_cause"],
    "debunked": [],
}


def award_from_verdict(finding: dict, verdict: str) -> dict:
    """Bridge from collab.py: award XP for a finding a debate reached a verdict on.

    finding: {title/name, target, cwe/class, hypothesis/summary, gates_passed?}
    verdict: "CONFIRMED" | "NEEDS MORE WORK" | "DEBUNKED" (case-insensitive).
    A DEBUNKED finding earns nothing (but is not an error). Returns the same
    shape as award_for_candidate, or {"skipped": True, ...} when no XP applies.
    """
    v = (verdict or "").strip().lower()
    gates = _VERDICT_GATES.get(v, [])
    if not gates:
        return {"skipped": True, "verdict": verdict, "xp_gained": 0}
    meta = {
        "title": finding.get("title") or finding.get("name") or "debate finding",
        "target": finding.get("target") or "unknown",
        "cwe": finding.get("cwe") or finding.get("class") or "",
        "hypothesis": finding.get("hypothesis") or finding.get("summary") or "",
        "gates_passed": finding.get("gates_passed") or gates,
        "verified": False,  # a debate never proves gates 2/3 — a PoC does
    }
    return award_for_candidate(meta)


def leaderboard() -> str:
    """A compact, human-readable standings block for the CLI (`run.py progression`)."""
    from collections import Counter
    snap = snapshot()
    c = snap["counts"]
    tgt = Counter()
    cwe = Counter()
    for b in snap["ledger"]:
        if b.get("verified"):
            tgt[b.get("target", "?")] += 1
        cl = (b.get("cwe") or "").strip()
        if cl:
            cwe[cl] += 1
    lines = [
        f"╔═ ARGUS HUNTER · Lv {snap['level']}  {snap['rank']} " + "═" * 6,
        f"║ XP {snap['xp_total']:,}   ({snap['xp_into_level']}/{snap['xp_for_next']} to Lv {snap['level']+1})",
        f"║ candidates {c['candidates']}   confirmed {c['verified']}   CWE classes {c['distinct_cwe']}",
        f"║ achievements {c['achievements']}/{c['achievements_total']}",
    ]
    if tgt:
        lines.append("║ top confirmed targets: " + ", ".join(f"{t} ({n})" for t, n in tgt.most_common(5)))
    if cwe:
        lines.append("║ top classes: " + ", ".join(f"{k} ({n})" for k, n in cwe.most_common(5)))
    lines.append("╚" + "═" * 34)
    return "\n".join(lines)


def reset() -> None:
    """Wipe progression state (fresh start)."""
    with _LOCK:
        if config.PROGRESSION_FILE.exists():
            config.PROGRESSION_FILE.unlink()


def snapshot() -> dict:
    """Full state for the web panel: HUD numbers, achievements, and the ledger."""
    with _LOCK:
        state = _load()
        stats = _stats(state)
        level = stats["level"]
        rank = rank_for_level(level)
        unlocked = set(state["achievements"])
        achievements = [{
            "id": aid, "name": name, "desc": desc, "icon": icon,
            "xp": bonus, "unlocked": aid in unlocked,
        } for aid, name, desc, icon, bonus, _ in ACHIEVEMENTS]
        ledger = sorted(state["bugs"].values(), key=lambda b: b.get("last_seen", ""), reverse=True)
        next_rank = rank["next"]
        return {
            "level": level,
            "xp_total": state["xp_total"],
            "xp_into_level": stats["xp_into_level"],
            "xp_for_next": stats["xp_for_next"],
            "progress_pct": round(100 * stats["xp_into_level"] / max(1, stats["xp_for_next"]), 1),
            "rank": rank["name"], "rank_color": rank["color"],
            "next_rank": next_rank,
            "counts": {
                "candidates": stats["candidates"], "verified": stats["verified"],
                "distinct_cwe": stats["distinct_cwe"], "records": stats["records"],
                "achievements": len(unlocked), "achievements_total": len(ACHIEVEMENTS),
            },
            "ranks": [{"min_level": m, "name": n, "color": c} for m, n, c in RANKS],
            "achievements": achievements,
            "ledger": ledger,
            "events": state["events"][:30],
        }
