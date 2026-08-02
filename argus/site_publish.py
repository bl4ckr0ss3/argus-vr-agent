"""Publish findings to a static site (GitHub Pages) by writing report files into
a local clone of the site repo and `git push`-ing. Host-side only.

Configuration (environment):
  ARGUS_SITE_DIR     local path to a clone of the site repo (REQUIRED)
  ARGUS_SITE_SUBDIR  sub-directory for findings within the repo (default: findings)
  ARGUS_SITE_URL     public base URL, for building links (e.g. https://0xblack.dev)
  ARGUS_SITE_PUSH    "0" to commit but not push (default: push)
  ARGUS_SITE_BRANCH  branch to push (default: current)

Git authentication is whatever the clone already uses (SSH key or credential
helper) — no tokens are handled here. Never point this at the detonation VM.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from . import report as R


def _cfg():
    d = os.environ.get("ARGUS_SITE_DIR", "").strip().strip('"')
    return {
        "dir": Path(d) if d else None,
        "subdir": os.environ.get("ARGUS_SITE_SUBDIR", "findings").strip("/ "),
        "url": os.environ.get("ARGUS_SITE_URL", "").strip().rstrip("/"),
        "push": os.environ.get("ARGUS_SITE_PUSH", "1") != "0",
        "branch": os.environ.get("ARGUS_SITE_BRANCH", "").strip(),
    }


def site_configured() -> bool:
    c = _cfg()
    return bool(c["dir"] and c["dir"].is_dir())


def analysis_url(sha256: str) -> str | None:
    """Public URL of a finding's report page, derivable from the hash alone
    (the report slug is sha-only). None if no public base URL is configured."""
    c = _cfg()
    if not c["url"] or len(sha256 or "") != 64:
        return None
    return f"{c['url']}/{c['subdir']}/{sha256[:16]}.html"


def status() -> dict:
    c = _cfg()
    ok = bool(c["dir"] and c["dir"].is_dir())
    is_git = ok and (c["dir"] / ".git").exists()
    return {"configured": ok, "is_git_repo": is_git, "dir": str(c["dir"]) if c["dir"] else None,
            "subdir": c["subdir"], "url": c["url"], "push": c["push"]}


def _git(dir_: Path, *args, timeout=60) -> tuple[int, str]:
    try:
        p = subprocess.run(["git", "-C", str(dir_), *args], capture_output=True,
                           text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).strip()
    except Exception as e:
        return 1, str(e)


def _load_feed(fdir: Path) -> list[dict]:
    f = fdir / "feed.json"
    if f.exists():
        try:
            return json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            return []
    return []


def publish_finding(struct: dict, do_push: bool | None = None) -> dict:
    """Write one finding's report into the site repo, refresh index + feed, and
    commit (+push). Returns {ok, url?, file?, pushed?, error?}. Idempotent per
    sha256 — re-publishing updates the existing report instead of duplicating."""
    c = _cfg()
    if not (c["dir"] and c["dir"].is_dir()):
        return {"ok": False, "error": "ARGUS_SITE_DIR is not set to a valid directory"}
    sha = (struct.get("sha256") or "").strip()
    if len(sha) != 64:
        return {"ok": False, "error": "finding has no sha256"}

    fdir = c["dir"] / c["subdir"]
    fdir.mkdir(parents=True, exist_ok=True)
    gen = R.now_utc()
    sl = R.slug(struct, gen)
    fname = f"{sl}.html"

    # write the report page
    (fdir / fname).write_text(R.report_html(struct, gen), encoding="utf-8")

    # refresh feed (dedup by sha256, newest first)
    feed = [e for e in _load_feed(fdir) if e.get("sha256") != sha]
    view = R.finding_view(struct)
    feed.insert(0, {"date": gen[:10], "generated": gen, "sample": view["sample"],
                    "sha256": sha, "verdict": view["verdict"],
                    "confidence": view["confidence"], "file": fname})
    feed.sort(key=lambda e: e.get("generated", ""), reverse=True)
    (fdir / "feed.json").write_text(json.dumps(feed, indent=2), encoding="utf-8")
    (fdir / "index.html").write_text(R.index_html(feed), encoding="utf-8")

    # commit (+ push)
    rel = c["subdir"]
    _git(c["dir"], "add", rel)
    code, msg = _git(c["dir"], "commit", "-m", f"Add finding: {view['sample']} ({view['verdict']} {view['confidence']}%)")
    committed = code == 0 or "nothing to commit" in msg
    pushed, push_msg = None, ""
    want_push = c["push"] if do_push is None else do_push
    if want_push:
        args = ["push"] + (["origin", c["branch"]] if c["branch"] else [])
        pc, push_msg = _git(c["dir"], *args, timeout=120)
        pushed = pc == 0
    url = f"{c['url']}/{c['subdir']}/{fname}" if c["url"] else f"{c['subdir']}/{fname}"
    return {"ok": True, "url": url, "file": fname, "committed": committed,
            "pushed": pushed, "push_msg": push_msg[:300] if push_msg else "",
            "count": len(feed)}
