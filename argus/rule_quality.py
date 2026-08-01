"""Rule quality gate — verify a YARA rule before it goes live.

Two checks, in order:
  1. compile — does the rule actually parse/compile? (yara-python or the yara
     CLI; a lightweight structural check as a last-resort fallback)
  2. false-positive scan — does it match anything in the known-benign corpus
     (config.GOODWARE_DIR)? A rule that hits goodware is too broad.

A rule PASSES only if it compiles and matches no goodware. With no goodware
corpus present the FP test is skipped (compile still gates) and the result is
flagged unverified so the operator knows breadth wasn't tested.

Used to hard-gate `yara --promote` (our own generated rules) and to give an
advisory compile summary on `rules --enable`.
"""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path

import config
from . import yara_engine

_HAS_RULE = re.compile(r"\brule\s+\w+", re.I)


def _structural(text: str) -> tuple[bool, str | None]:
    """Cheap syntax sanity check for when no YARA engine is installed."""
    if not _HAS_RULE.search(text):
        return False, "no 'rule <name>' declaration"
    if "condition:" not in text:
        return False, "no 'condition:' section"
    if text.count("{") != text.count("}"):
        return False, "unbalanced braces"
    return True, None


def compile_ok(text: str) -> dict:
    """Return {ok, error, verified}. verified=True only if a real YARA engine
    compiled it (structural-only fallback sets verified=False)."""
    ok, how = yara_engine.available()
    if ok and how == "yara-python":
        try:
            import yara
            yara.compile(source=text)
            return {"ok": True, "error": None, "verified": True}
        except Exception as e:
            return {"ok": False, "error": str(e)[:200], "verified": True}
    if ok:  # CLI binary: compile by scanning a throwaway file; stderr => compile error
        try:
            with tempfile.TemporaryDirectory() as td:
                rf = Path(td) / "r.yar"; rf.write_text(text, encoding="utf-8")
                tf = Path(td) / "t.bin"; tf.write_bytes(b"\x00" * 16)
                r = subprocess.run([how, str(rf), str(tf)], capture_output=True, text=True, timeout=30)
                if r.returncode != 0 and r.stderr.strip():
                    return {"ok": False, "error": r.stderr.strip()[:200], "verified": True}
                return {"ok": True, "error": None, "verified": True}
        except Exception as e:
            return {"ok": False, "error": str(e)[:200], "verified": True}
    ok2, err = _structural(text)
    return {"ok": ok2, "error": err, "verified": False}


def goodware_files(limit: int = 400) -> list[Path]:
    d = config.GOODWARE_DIR
    if not d.exists():
        return []
    return [p for p in sorted(d.rglob("*")) if p.is_file()][:limit]


def _matches(rule_path: str | Path, target: str | Path) -> bool:
    """Does `rule_path` match `target`? (mockable unit for tests)."""
    ok, how = yara_engine.available()
    if not ok:
        return False
    if how == "yara-python":
        try:
            import yara
            return bool(yara.compile(filepath=str(rule_path)).match(str(target)))
        except Exception:
            return False
    try:
        r = subprocess.run([how, str(rule_path), str(target)], capture_output=True, text=True, timeout=30)
        return bool(r.stdout.strip())
    except Exception:
        return False


def scan_goodware(rule_path: str | Path, limit: int = 400) -> dict:
    files = goodware_files(limit)
    hits = [str(f) for f in files if _matches(rule_path, f)]
    return {"scanned": len(files), "hits": hits}


def check_file(rule_path: str | Path) -> dict:
    """Full gate on a rule FILE. Returns a verdict dict (never raises)."""
    p = Path(rule_path)
    try:
        text = p.read_text(encoding="utf-8", errors="ignore")
    except OSError as e:
        return {"passed": False, "compiles": False, "reasons": [f"unreadable: {e}"]}

    comp = compile_ok(text)
    gw = scan_goodware(p) if comp["ok"] else {"scanned": 0, "hits": []}
    reasons = []
    if not comp["ok"]:
        reasons.append(f"does not compile: {comp['error']}")
    if gw["hits"]:
        reasons.append(f"matches {len(gw['hits'])} goodware file(s) — too broad")
    if comp["ok"] and gw["scanned"] == 0:
        reasons.append("no goodware corpus — FP breadth not tested (set ARGUS_GOODWARE)")
    return {
        "passed": comp["ok"] and not gw["hits"],
        "compiles": comp["ok"], "verified": comp["verified"], "error": comp["error"],
        "goodware_scanned": gw["scanned"], "fp_hits": gw["hits"], "reasons": reasons,
    }


def check_text(text: str) -> dict:
    """Full gate on rule TEXT (for a generated rule before it is saved)."""
    fd, tmp = tempfile.mkstemp(suffix=".yar")
    try:
        os.write(fd, text.encode("utf-8"))
        os.close(fd)
        return check_file(tmp)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def compile_summary(files: list[Path]) -> dict:
    """Fast compile-only pass over many rule files (advisory, no goodware scan)."""
    ok, fail = 0, []
    for f in files:
        try:
            if compile_ok(f.read_text(encoding="utf-8", errors="ignore"))["ok"]:
                ok += 1
            else:
                fail.append(f.name)
        except OSError:
            fail.append(f.name)
    return {"ok": ok, "fail": len(fail), "fail_names": fail[:20], "total": len(files)}
