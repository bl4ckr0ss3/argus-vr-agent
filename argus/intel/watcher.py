"""Intake watcher — the autonomous half of the pipeline.

Polls config.INTAKE_DIR for new files (from the MalwareBazaar feed, a honeypot,
or dropped by hand), unpacks archives into quarantine, runs STATIC triage on
each new sample, and writes:
  - a per-sample report note into the Obsidian vault (Malware Intel/Reports/)
  - a line into intel/ledger.jsonl
  - a regenerated Malware Intel/Dashboard.md

Deterministic static analysis runs for FREE (no LLM). Pass llm=True to also have
ARGUS write a narrative analyst summary per sample (costs tokens). Nothing is
ever executed. Run inside an isolated VM.
"""
from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path

import config
from .. import yara_engine
from ..tools.malware import analyze_file, unpack_archive

SEEN_FILE = config.INTEL_DIR / "seen.json"
LEDGER_FILE = config.INTEL_DIR / "ledger.jsonl"


# --- persistence -----------------------------------------------------------
def _load_seen() -> set[str]:
    if SEEN_FILE.exists():
        try:
            return set(json.loads(SEEN_FILE.read_text(encoding="utf-8")))
        except Exception:
            return set()
    return set()


def _save_seen(seen: set[str]) -> None:
    config.INTEL_DIR.mkdir(parents=True, exist_ok=True)
    SEEN_FILE.write_text(json.dumps(sorted(seen)), encoding="utf-8")


# --- static heuristic verdict (clearly labelled, not ground truth) ---------
_INJECT = {"VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
           "NtCreateThreadEx", "QueueUserAPC", "SetThreadContext"}
_DOWNLOAD = {"URLDownloadToFile", "InternetOpen", "InternetConnect", "WinHttpOpen", "HttpSendRequest"}
_PERSIST = {"RegSetValue", "RegCreateKey", "CreateService", "StartService"}
_KEYLOG = {"SetWindowsHookEx", "GetAsyncKeyState", "GetKeyboardState"}
_ANTIDBG = {"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"}


def heuristic_verdict(a: dict) -> tuple[str, int, list[str]]:
    score, reasons = 0, []
    apis = set(a.get("apis", []))
    pe = a.get("pe")
    if len(_INJECT & apis) >= 2:
        score += 3; reasons.append("process-injection API combo")
    if _DOWNLOAD & apis:
        score += 2; reasons.append("payload-download APIs")
    if _KEYLOG & apis:
        score += 2; reasons.append("keylogging APIs")
    if _PERSIST & apis:
        score += 1; reasons.append("persistence APIs")
    if _ANTIDBG & apis:
        score += 1; reasons.append("anti-debug APIs")
    if pe and pe.get("high_entropy_sections"):
        score += 2; reasons.append(f"high-entropy sections {pe['high_entropy_sections']} (packing/encryption)")
    if pe and len(pe.get("imports", [])) <= 2 and a["entropy"] >= 7:
        score += 2; reasons.append("very few imports + high entropy (likely packed)")
    if a["iocs"].get("url") or a["iocs"].get("ipv4"):
        score += 1; reasons.append("network IOCs present")
    verdict = "likely-malicious" if score >= 5 else "suspicious" if score >= 2 else "low-signal"
    return verdict, score, reasons


# --- report + ledger + dashboard -------------------------------------------
def _report_md(a: dict, source: str, verdict: str, score: int, reasons: list[str], llm_summary: str, stamp: str) -> str:
    ioc_lines = []
    for kind, vals in a["iocs"].items():
        for v in vals:
            ioc_lines.append(f"| {kind} | `{v}` |")
    pe = a.get("pe")
    pe_block = ""
    if pe:
        kind = "DLL" if pe["is_dll"] else "EXE"
        imports_str = ", ".join(pe["imports"][:25]) or "(none parsed)"
        sec_str = ", ".join("{}(ent {})".format(s["name"], s["entropy"]) for s in pe["sections"])
        pe_block = (
            f"- **PE:** {pe['arch']} {kind} · subsystem={pe['subsystem']} · compiled={pe['compiled']}\n"
            f"- **Imported DLLs ({len(pe['imports'])}):** {imports_str}\n"
            f"- **Sections:** {sec_str}\n"
        )
        if pe["high_entropy_sections"]:
            pe_block += f"- ⚠ **High-entropy sections:** {', '.join(pe['high_entropy_sections'])}\n"
    return f"""---
type: malware-report
source: argus-intel
origin: {source}
sha256: {a['hashes']['sha256']}
verdict: {verdict}
created: {stamp}
---

# {a['name']} — {verdict} (static heuristic score {score})

> STATIC triage only — the sample was never executed. Verdict is a static
> heuristic, not ground truth; confirm with dynamic analysis in an isolated VM.

## Identification
- **sha256:** `{a['hashes']['sha256']}`
- **md5:** `{a['hashes']['md5']}`   **sha1:** `{a['hashes']['sha1']}`
- **size:** {a['size']} bytes   **type:** {a['type']}   **entropy:** {a['entropy']}
{pe_block}
## Heuristic verdict: {verdict}
{chr(10).join(f'- {r}' for r in reasons) or '- no strong static signals'}

## Suspicious API surface
{', '.join(a['apis']) or '(none)'}

## IOCs
| type | value |
|------|-------|
{chr(10).join(ioc_lines) or '| — | none extracted |'}
{('## ARGUS analyst summary' + chr(10) + chr(10) + llm_summary + chr(10)) if llm_summary else ''}
## Links
- [[Dashboard]]
"""


def _append_ledger(entry: dict) -> None:
    config.INTEL_DIR.mkdir(parents=True, exist_ok=True)
    with LEDGER_FILE.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")


def _regenerate_dashboard() -> None:
    if not LEDGER_FILE.exists():
        return
    rows = []
    for line in LEDGER_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    rows = rows[-500:][::-1]  # newest first
    counts = {}
    for r in rows:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    hdr = " · ".join(f"{k}: {v}" for k, v in sorted(counts.items())) or "no samples yet"
    lines = [
        "---", "type: dashboard", "title: Malware Intel", "---", "",
        "# 🦠 Malware Intel — Autonomous Triage",
        "",
        "> Auto-generated by the ARGUS intake watcher. STATIC triage only — no sample executed.",
        "",
        f"**Totals:** {len(rows)} samples · {hdr}",
        "",
        "| when | verdict | type | sha256 | IOCs | report |",
        "|------|---------|------|--------|------|--------|",
    ]
    for r in rows[:200]:
        ioc = r.get("ioc_total", 0)
        rep = f"[[{Path(r['report']).stem}]]" if r.get("report") else "—"
        lines.append(f"| {r['ts'][:16]} | {r['verdict']} | {r.get('type','?')[:22]} | `{r['sha256'][:16]}…` | {ioc} | {rep} |")
    config.INTEL_VAULT_DIR.mkdir(parents=True, exist_ok=True)
    (config.INTEL_VAULT_DIR / "Dashboard.md").write_text("\n".join(lines), encoding="utf-8")


def _slug(s: str) -> str:
    import re
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:40] or "sample"


def _triage_sample(path: Path, source: str, seen: set[str], llm: bool) -> dict | None:
    a = analyze_file(path)
    sha = a["hashes"]["sha256"]
    if sha in seen:
        return None
    seen.add(sha)
    verdict, score, reasons = heuristic_verdict(a)
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    llm_summary = ""
    if llm:
        try:
            from ..agent import Argus
            agent = Argus(verbose=False, mode="triage")
            if agent.ready:
                task = (f"Static triage summary for the already-analyzed sample at {path} "
                        f"(sha256 {sha}). Call triage_report on it, then give a concise analyst "
                        f"verdict, capability hypotheses, and next dynamic-analysis steps.")
                llm_summary = agent.run(task, max_steps=8).final_text
        except Exception as e:
            llm_summary = f"(LLM summary unavailable: {e})"

    config.INTEL_VAULT_DIR.mkdir(parents=True, exist_ok=True)
    reports = config.INTEL_VAULT_DIR / "Reports"
    reports.mkdir(parents=True, exist_ok=True)
    note = reports / f"{sha[:16]}-{_slug(a['name'])}.md"
    note.write_text(_report_md(a, source, verdict, score, reasons, llm_summary, stamp), encoding="utf-8")

    ioc_total = sum(len(v) for v in a["iocs"].values())
    entry = {"ts": datetime.now().isoformat(timespec="seconds"), "sha256": sha,
             "name": a["name"], "type": a["type"], "verdict": verdict, "score": score,
             "ioc_total": ioc_total, "source": source, "report": str(note)}
    _append_ledger(entry)
    return entry


def poll_once(llm: bool = False, verbose: bool = True) -> list[dict]:
    config.INTAKE_DIR.mkdir(parents=True, exist_ok=True)
    seen = _load_seen()
    new_entries: list[dict] = []
    for f in sorted(config.INTAKE_DIR.iterdir()):
        if not f.is_file() or f.name.lower() in ("readme.md", "readme.txt", ".gitkeep"):
            continue
        try:
            extracted, meta = unpack_archive(f)
        except Exception as e:
            if verbose:
                print(f"  ! unpack failed for {f.name}: {e}")
            continue
        for s in extracted:
            entry = _triage_sample(s, source=f.name, seen=seen, llm=llm)
            if entry:
                new_entries.append(entry)
                if verbose:
                    print(f"  [{entry['verdict']:>16}] {entry['sha256'][:16]}  {entry['name']}  ({entry['ioc_total']} IOCs)")
    if new_entries:
        _save_seen(seen)
        _regenerate_dashboard()
    return new_entries


def watch(interval: int = 60, llm: bool = False, once: bool = False) -> None:
    print(f"ARGUS intake watcher — polling {config.INTAKE_DIR} every {interval}s "
          f"(llm={'on' if llm else 'off'}). Static only. Ctrl+C to stop.")
    while True:
        n = poll_once(llm=llm)
        if not once:
            time.sleep(max(5, interval))
        else:
            print(f"done ({len(n)} new).")
            return
