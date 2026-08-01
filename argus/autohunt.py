"""ARGUS autonomous hunt loop.

Ties the pieces together into a self-running pipeline:

    queue (samples)  ->  detonate  ->  auto-analyze  ->  verdict
                                                          |
                    +-------------------------------------+
                    |                          |
              log to ledger (+XP)        if suspicious:
                                         draft a writeup into the
                                         REVIEW QUEUE (human-gated)

Design constraints that make this safe to run *inside the detonation VM*:
  - Zero LLM calls: the verdict is the heuristic from tools/dynamic.py and the
    writeup is a template. So the loop needs NO API key — which is exactly what
    the credential guard wants (no secrets on the machine that runs malware).
  - Nothing is ever published. A suspicious verdict produces DRAFTS in a review
    queue (report + tweet + findings.json) marked `pending-review`. A human
    approves before anything reaches VirusTotal / Twitter / LinkedIn. The
    hyper-grid false-positive is why: an auto-poster would have publicly accused
    a benign app of being malware.
  - Idempotent: each sample is keyed by SHA-256; an already-processed sample is
    skipped, so the loop can be restarted safely.

State lives under config.STATE_DIR; drafts under RUNS_DIR/review_queue/.
"""
from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import config
from . import progression
from .tools.dynamic import run_detonation

# Where drafts await human approval, and where we remember what we've seen.
REVIEW_DIR = config.RUNS_DIR / "review_queue"
_SEEN_FILE = config.STATE_DIR / "autohunt_seen.json"
# Sample extensions the loop will pick up from the queue directory.
_SAMPLE_EXTS = {".exe", ".dll", ".bin", ".sys", ".scr", ".msi", ".ps1",
                ".js", ".vbs", ".jar", ".bat", ".cmd", ".com", ".sample", ""}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_seen() -> dict:
    try:
        return json.loads(_SEEN_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_seen(seen: dict) -> None:
    _SEEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = _SEEN_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(seen, indent=2), encoding="utf-8")
    tmp.replace(_SEEN_FILE)


def _is_pe(p: Path) -> bool:
    try:
        with open(p, "rb") as f:
            return f.read(2) == b"MZ"
    except OSError:
        return False


def _iter_queue(queue_dir: Path):
    """Yield detonatable sample files in the queue (non-recursive).

    A `.zip` (MalwareBazaar / sample feeds ship AES-encrypted zips, password
    'infected') is unpacked automatically and its PE members are yielded, so
    `fetch -> autohunt` works end-to-end with no manual extraction."""
    if not queue_dir.exists():
        return
    for p in sorted(queue_dir.iterdir()):
        if not p.is_file():
            continue
        if p.suffix.lower() == ".zip":
            try:
                from .tools.malware import unpack_archive
                extracted, _meta = unpack_archive(p)
            except Exception:
                continue
            for ex in extracted:
                if _is_pe(ex) or ex.suffix.lower() in _SAMPLE_EXTS:
                    yield ex
        elif p.suffix.lower() in _SAMPLE_EXTS:
            yield p


# ---------------------------------------------------------------------------
# progression: a detonation that shows real behavior is a reproduced finding
# ---------------------------------------------------------------------------
def _record_finding(struct: dict) -> dict | None:
    """Award XP for a suspicious sample. Detonation = we RAN it and observed the
    behavior, so the `reproduced` gate is genuinely met; `impact` too when it
    persists / beacons / drops. We never claim root_cause or scope from a
    detonation alone. A benign/inconclusive verdict earns nothing."""
    if struct.get("verdict") != "suspicious":
        return None
    gates = ["reproduced"]
    if any(s in struct["signals"] for s in ("persistence", "network", "executable-drop")):
        gates.append("impact")
    meta = {
        "title": f"malware: {struct.get('sample') or struct.get('sha256', '?')[:12]}",
        "target": struct.get("sample") or struct.get("sha256", "unknown"),
        "cwe": "malware/" + "+".join(struct["signals"]),
        "hypothesis": struct.get("verdict_text", ""),
        "gates_passed": gates,
        "verified": False,
    }
    return progression.award_for_candidate(meta)


# ---------------------------------------------------------------------------
# review queue: draft artifacts, human approves before anything is published
# ---------------------------------------------------------------------------
def _draft_writeup(struct: dict) -> Path:
    """Write a pending-review draft bundle for a suspicious sample."""
    sha = struct.get("sha256", "") or "nohash"
    draft_dir = REVIEW_DIR / f"{sha[:16]}_{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    draft_dir.mkdir(parents=True, exist_ok=True)

    sample = struct.get("sample", "?")
    signals = ", ".join(struct["signals"]) or "none"

    # Markdown writeup (for LinkedIn / a blog / the disclosure record)
    md = [
        f"# Malware Triage - {sample}",
        f"_Draft generated {_now()} | **PENDING HUMAN REVIEW - do not publish as-is**_",
        "",
        f"- **SHA-256:** `{sha}`",
        f"- **Heuristic verdict:** {struct.get('verdict_text','')}",
        f"- **Confidence:** {struct.get('confidence','?')}% ({struct.get('confidence_label','?')})",
        f"- **Indicators:** {signals}",
    ]
    if struct.get("yara"):
        md.append("- **YARA:** " + ", ".join(struct["yara"][:10]))
    if struct.get("attack"):
        md.append("- **ATT&CK:** " + ", ".join(f"{t['id']} {t['name']}" for t in struct["attack"]))
    if struct.get("vt"):
        md.append(f"- **VirusTotal:** {struct['vt'].get('summary', 'n/a')}")
    if struct.get("vt_conflict"):
        md.append(f"- **VT conflict:** {struct['vt_conflict']}")
    md += ["", "## Observed behavior (dynamic)"]
    if struct["persistence"]:
        md.append("### Persistence")
        md += [f"- `{p}`" for p in struct["persistence"][:10]]
    if struct["net"]:
        md.append("### Network endpoints")
        md += [f"- `{n}`" for n in struct["net"][:20]]
    if struct["staged_payloads"]:
        md.append("### Dropped executables")
        md += [f"- `{f}`" for f in struct["staged_payloads"][:20]]
    if struct["spawned"]:
        md.append("### Child processes")
        md += [f"- `{s}`" for s in struct["spawned"][:20]]
    # extracted, defanged IOCs for sharing
    try:
        from . import ioc as _ioc
        iocs = _ioc.extract_from(struct, struct.get("static"))
        if any(iocs.values()):
            md.append("")
            md.append("## IOCs (defanged)")
            for cat, vals in iocs.items():
                if vals:
                    md.append(f"**{cat}**")
                    md += [f"- `{_ioc.defang(v, _ioc._KIND.get(cat, cat))}`" for v in vals[:15]]
    except Exception:
        pass

    md += [
        "",
        "## Reviewer checklist (before publishing)",
        "- [ ] Confirm the sample is actually malicious (rule out false positive).",
        "- [ ] Confirm you are permitted to disclose (no NDA / active case).",
        "- [ ] Sanity-check IOCs; redact anything that identifies a victim.",
        "- [ ] Verify the family/attribution claim, if any.",
    ]
    (draft_dir / "writeup.md").write_text("\n".join(md), encoding="utf-8")

    # Tweet draft (280-char budget, IOC-light, hedged language)
    net_hint = f" - beacons {len(struct['net'])} endpoint(s)" if struct["net"] else ""
    tweet = (f"#malware triage: {sample} (SHA256 {sha[:12]}...) shows "
             f"{signals}{net_hint}. Dynamic analysis via ARGUS. "
             f"#threatintel #DFIR")
    (draft_dir / "tweet.txt").write_text(tweet[:280], encoding="utf-8")

    # Machine-readable record + explicit gate marker
    (draft_dir / "findings.json").write_text(json.dumps(struct, indent=2), encoding="utf-8")
    (draft_dir / "STATUS").write_text("pending-review\n", encoding="utf-8")
    return draft_dir


# ---------------------------------------------------------------------------
# the loop
# ---------------------------------------------------------------------------
def process_sample(sample: Path, timeout: int, on_event=None) -> dict:
    """Detonate one sample, analyze, record, and draft if suspicious."""
    def ev(kind, **kw):
        if on_event:
            try:
                on_event({"type": kind, "sample": sample.name, **kw})
            except Exception:
                pass

    ev("start")
    res: dict = {}
    run_detonation(str(sample), timeout, on_progress=None, result=res)

    if res.get("blocked"):
        ev("blocked", keys=res.get("blocked_keys", []))
        return {"status": "blocked", **res}
    if res.get("error"):
        ev("error", error=res["error"])
        return {"status": "error", **res}

    # Corroborate with VirusTotal when a key is available (no-op in the keyless
    # VM; runs on the host). Persist the enriched struct back to findings.json.
    try:
        from .intel import virustotal
        if virustotal.available():
            virustotal.enrich(res)
            (Path(res["out_dir"]) / "findings.json").write_text(
                json.dumps(res, indent=2), encoding="utf-8")
            if res.get("vt_conflict"):
                ev("vt_conflict", note=res["vt_conflict"])
    except Exception:
        pass

    verdict = res.get("verdict", "inconclusive")

    # Grow our own detection set: stage a candidate YARA rule for a high-confidence
    # suspicious sample. STAGED only (rules/generated/) - promotion is a human step,
    # so an over-broad auto-rule can't start firing false positives on its own.
    if verdict == "suspicious" and res.get("confidence", 0) >= 70:
        try:
            from . import yara_gen
            rule = yara_gen.generate_rule(
                sample, name=sample.stem,
                meta={"verdict": res.get("verdict"), "description": res.get("verdict_text", "")})
            if not rule.get("error"):
                res["yara_rule"] = str(yara_gen.save_generated(rule))
                ev("rule_staged", rule=res["yara_rule"])
        except Exception:
            pass

    award = _record_finding(res)
    draft = None
    if verdict == "suspicious":
        draft = _draft_writeup(res)
        ev("drafted", verdict=verdict, draft=str(draft),
           xp=(award or {}).get("xp_gained", 0), level=(award or {}).get("level"))
    else:
        ev("done", verdict=verdict)
    return {"status": "ok", "verdict": verdict, "draft": str(draft) if draft else None,
            "award": award, **res}


def loop(queue_dir: Path | None = None, timeout: int = 120,
         once: bool = False, interval: int = 30, on_event=None) -> None:
    """Continuously drain the sample queue. Idempotent by SHA-256."""
    queue_dir = Path(queue_dir) if queue_dir else config.INTAKE_DIR
    REVIEW_DIR.mkdir(parents=True, exist_ok=True)

    def ev(kind, **kw):
        if on_event:
            try:
                on_event({"type": kind, **kw})
            except Exception:
                pass

    ev("loop_start", queue=str(queue_dir), once=once)
    while True:
        seen = _load_seen()
        processed_any = False
        for sample in _iter_queue(queue_dir):
            try:
                sha = _sha256(sample)
            except OSError:
                continue
            if sha in seen:
                continue
            processed_any = True
            outcome = process_sample(sample, timeout, on_event=on_event)

            if outcome.get("status") == "blocked":
                # keys present -> the whole VM is unsafe; stop rather than spin.
                ev("halt", reason="credentials present — remove keys from this VM")
                return
            seen[sha] = {
                "sample": sample.name, "verdict": outcome.get("verdict"),
                "status": outcome.get("status"), "draft": outcome.get("draft"),
                "ts": _now(),
            }
            _save_seen(seen)

        if once:
            ev("loop_end", processed=processed_any)
            return
        if not processed_any:
            ev("idle", waiting=interval)
        time.sleep(max(5, interval))


def pending_reviews() -> list[dict]:
    """List draft bundles still awaiting human approval (for the CLI / panel)."""
    out = []
    if not REVIEW_DIR.exists():
        return out
    for d in sorted(REVIEW_DIR.iterdir(), reverse=True):
        status_f = d / "STATUS"
        if d.is_dir() and status_f.exists():
            out.append({
                "dir": str(d),
                "status": status_f.read_text(encoding="utf-8").strip(),
                "tweet": (d / "tweet.txt").read_text(encoding="utf-8") if (d / "tweet.txt").exists() else "",
            })
    return out
