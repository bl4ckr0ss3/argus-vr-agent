"""Golden-verdict validation harness — `python run.py selftest`.

Unit tests prove the LOGIC is correct; this proves the pipeline agrees with KNOWN
ground truth. You declare cases in a manifest (a sample/dump/run + its expected
outcome) and selftest runs the relevant analysis and asserts the match — turning
"does it work on real malware?" into a repeatable regression.

Case types (NONE execute a sample — safe to run anywhere):
  static   — static analysis + YARA on a file      (EICAR, clean bins, packed samples)
  memscan  — Volatility3 cross-view on a dump       (a known-rootkit memory image)
  findings — validate a COMPLETED detonation's findings.json against expectations

Expectations supported: verdict, verdict_not, yara_any, yara_rule, packed,
signal, hidden_process, hidden_driver, severity. Exit is non-zero if any case
fails, so it can gate CI.
"""
from __future__ import annotations

import json
from pathlib import Path


def _eval_static(case: dict) -> dict:
    from .tools.malware import analyze_file
    from . import yara_engine
    p = Path(case["file"])
    if not p.exists():
        return {"error": f"missing file: {p}"}
    static = analyze_file(p)
    entropy = static.get("entropy") or (static.get("pe", {}) or {}).get("entropy") or 0
    return {
        "yara": yara_engine.scan_file(str(p)),
        "packed": bool(isinstance(entropy, (int, float)) and entropy >= 7.2),
        "entropy": entropy, "type": static.get("type"),
    }


def _eval_memscan(case: dict) -> dict:
    from . import memscan
    r = memscan.scan(case["dump"])
    if r.get("error"):
        return {"error": r["error"]}
    f = r["findings"]
    return {
        "hidden_process": any(x["what"].startswith("hidden process") for x in f),
        "hidden_driver": any(x["what"].startswith("hidden driver") for x in f),
        "severities": [x["severity"] for x in f],
    }


def _eval_findings(case: dict) -> dict:
    p = Path(case["path"])
    fj = (p / "findings.json") if p.is_dir() else p
    if not fj.exists():
        return {"error": f"no findings.json: {fj}"}
    return json.loads(fj.read_text(encoding="utf-8"))


_EVAL = {"static": _eval_static, "memscan": _eval_memscan, "findings": _eval_findings}


def check_expect(expect: dict, result: dict) -> tuple[bool, list[str]]:
    """Pure comparison of expectations against an analysis result."""
    if "error" in result:
        return False, [result["error"]]
    reasons: list[str] = []
    for k, v in expect.items():
        if k == "verdict" and result.get("verdict") != v:
            reasons.append(f"verdict {result.get('verdict')!r} != {v!r}")
        elif k == "verdict_not" and result.get("verdict") == v:
            reasons.append(f"verdict is {v!r} (must not be)")
        elif k == "yara_any" and bool(result.get("yara")) != v:
            reasons.append(f"yara_any {bool(result.get('yara'))} != {v}")
        elif k == "yara_rule" and v not in (result.get("yara") or []):
            reasons.append(f"yara rule {v!r} not matched (got {result.get('yara')})")
        elif k == "packed" and bool(result.get("packed")) != v:
            reasons.append(f"packed {bool(result.get('packed'))} != {v}")
        elif k == "signal" and v not in (result.get("signals") or []):
            reasons.append(f"signal {v!r} absent (got {result.get('signals')})")
        elif k == "hidden_process" and bool(result.get("hidden_process")) != v:
            reasons.append(f"hidden_process {bool(result.get('hidden_process'))} != {v}")
        elif k == "hidden_driver" and bool(result.get("hidden_driver")) != v:
            reasons.append(f"hidden_driver {bool(result.get('hidden_driver'))} != {v}")
        elif k == "severity" and v not in (result.get("severities") or []):
            reasons.append(f"no {v} finding (got {result.get('severities')})")
        elif k not in ("verdict", "verdict_not", "yara_any", "yara_rule", "packed",
                       "signal", "hidden_process", "hidden_driver", "severity"):
            reasons.append(f"unknown expectation '{k}'")
    return (not reasons), reasons


def run_manifest(manifest_path: str) -> dict:
    mp = Path(manifest_path)
    if not mp.exists():
        return {"error": f"no manifest: {mp}"}
    manifest = json.loads(mp.read_text(encoding="utf-8"))
    base = mp.parent
    out = []
    for case in manifest.get("cases", []):
        name = case.get("name", "?")
        # resolve relative sample/dump/run paths against the manifest's directory
        for key in ("file", "dump", "path"):
            if key in case and not Path(case[key]).is_absolute():
                case[key] = str(base / case[key])
        ev = _EVAL.get(case.get("type"))
        if not ev:
            out.append({"name": name, "status": "error", "reasons": [f"unknown type {case.get('type')!r}"]})
            continue
        try:
            result = ev(case)
        except Exception as e:  # a broken case must not sink the whole run
            out.append({"name": name, "status": "error", "reasons": [f"{type(e).__name__}: {e}"]})
            continue
        ok, reasons = check_expect(case.get("expect", {}), result)
        out.append({"name": name, "type": case.get("type"),
                    "status": "pass" if ok else "fail", "reasons": reasons})
    passed = sum(1 for c in out if c["status"] == "pass")
    return {"cases": out, "passed": passed,
            "failed": len(out) - passed, "total": len(out)}
