"""Autonomous publishing gate + daemon.

Watches the review queue and auto-publishes findings that clear a confidence
threshold AND the safety gate, to the configured targets (VirusTotal comment +
static site). Everything below the threshold, or that the safety gate flags,
is left in the panel for a human to review — a wrong public "X is malware" is
defamatory and cannot be un-posted, so the bar to auto-publish is deliberately
high.

Config (environment):
  ARGUS_AUTOPUBLISH          "1" to start the daemon with the web server
  ARGUS_AUTOPUBLISH_MIN      confidence floor to auto-publish (default 85)
  ARGUS_AUTOPUBLISH_TARGETS  comma list: vt,site  (default "vt,site")
  ARGUS_AUTOPUBLISH_INTERVAL seconds between queue scans (default 120)
"""
from __future__ import annotations

import os
import threading
import time

from . import publish, site_publish

_state = {
    "enabled": False, "running": False, "last_scan": None,
    "published": 0, "skipped": 0, "failed": 0, "recent": [],
    "threshold": 85, "targets": ["vt", "site"],
}
_lock = threading.Lock()
_stop = threading.Event()
_thread: threading.Thread | None = None


def settings() -> dict:
    return {
        "threshold": int(os.environ.get("ARGUS_AUTOPUBLISH_MIN", "85")),
        "targets": [t.strip() for t in os.environ.get(
            "ARGUS_AUTOPUBLISH_TARGETS", "vt,site").split(",") if t.strip()],
        "interval": int(os.environ.get("ARGUS_AUTOPUBLISH_INTERVAL", "120")),
    }


def status() -> dict:
    with _lock:
        s = dict(_state)
    cfg = settings()
    s.update(threshold=cfg["threshold"], targets=cfg["targets"],
             interval=cfg["interval"], site=site_publish.status(),
             vt_ready=bool((getattr(__import__("config"), "VT_API_KEY", "") or "").strip()))
    return s


def _mark_published(draft_id: str) -> None:
    try:
        d = publish._resolve(draft_id)
        (d / "STATUS").write_text("published\n", encoding="utf-8")
    except Exception:
        pass


def publish_one(draft: dict, targets: list[str]) -> dict:
    """Publish a single eligible finding to the given targets. Returns a summary."""
    draft_id = draft["id"]
    info = publish.load_draft(draft_id)
    struct = info.get("struct", {}) or {}
    out = {"id": draft_id, "sample": draft.get("sample") or draft_id, "targets": {}}
    ok_any = False

    # Publish the site report FIRST so the VT comment's "Full Analysis" link is
    # already live when the comment goes out.
    if "site" in targets:
        r = site_publish.publish_finding(struct)
        if r.get("ok"):
            out["targets"]["site"] = r.get("url", "published")
            ok_any = True
        else:
            out["targets"]["site"] = r.get("error", "failed")

    # Everything the publish pipeline handles (vt comment+vote, twitter, linkedin).
    pub_targets = [t for t in targets if t in ("vt", "twitter", "linkedin")]
    if pub_targets:
        publish.approve(draft_id)  # safety gate still enforced inside publish()
        r = publish.publish(draft_id, pub_targets, confirm=True, force=False)
        if r.get("blocked"):
            for t in pub_targets:
                out["targets"][t] = r["blocked"]
        for res in r.get("results", []):
            tgt = res.get("target", "?")
            ok = bool(res.get("ok") and not res.get("skipped"))
            out["targets"][tgt] = "posted" if ok else res.get("detail", "skipped")
            ok_any = ok_any or ok

    if ok_any:
        _mark_published(draft_id)
    out["ok"] = ok_any
    return out


def eligible(drafts: list[dict], threshold: int) -> list[dict]:
    """Findings clear to auto-publish: unpublished, safety-cleared, >= threshold."""
    out = []
    for d in drafts:
        if d.get("status") == "published":
            continue
        if d.get("safety"):            # safety_reason non-None -> hold for review
            continue
        if (d.get("confidence") or 0) < threshold:
            continue
        out.append(d)
    return out


def backfill_site(dry: bool = False) -> dict:
    """Publish a SITE report for every suspicious, safety-cleared finding —
    regardless of VT-published status — to seed the website with existing work.
    Site-only (no VT re-posting); idempotent per sha256, one git push at the end."""
    import os as _os
    prev = _os.environ.get("ARGUS_SITE_PUSH")
    _os.environ["ARGUS_SITE_PUSH"] = "0"      # commit each, push once at the end
    results, published = [], 0
    try:
        for d in publish.list_drafts():
            if d.get("verdict") != "suspicious" or d.get("safety"):
                continue
            if dry:
                results.append({"sample": d.get("sample"), "would_publish": True})
                continue
            info = publish.load_draft(d["id"])
            r = site_publish.publish_finding(info.get("struct", {}) or {})
            results.append({"sample": d.get("sample"), "ok": r.get("ok"),
                            "url": r.get("url") or r.get("error")})
            if r.get("ok"):
                published += 1
    finally:
        if prev is None:
            _os.environ.pop("ARGUS_SITE_PUSH", None)
        else:
            _os.environ["ARGUS_SITE_PUSH"] = prev
    pushed = None
    if not dry and published and site_publish._cfg()["push"]:
        c = site_publish._cfg()
        code, msg = site_publish._git(c["dir"], "push", *( ["origin", c["branch"]] if c["branch"] else []), timeout=180)
        pushed = code == 0
    return {"eligible": len(results), "published": published, "pushed": pushed,
            "dry_run": dry, "results": results}


def scan_once(dry: bool = False) -> dict:
    cfg = settings()
    targets = cfg["targets"]
    drafts = publish.list_drafts()
    todo = eligible(drafts, cfg["threshold"])
    results = []
    for d in todo:
        if dry:
            results.append({"id": d["id"], "sample": d.get("sample"),
                            "confidence": d.get("confidence"), "would_publish": True})
            continue
        r = publish_one(d, targets)
        results.append(r)
        with _lock:
            if r["ok"]:
                _state["published"] += 1
            else:
                _state["failed"] += 1
            _state["recent"] = ([{"sample": r["sample"], **r["targets"]}] + _state["recent"])[:30]
        # pace VT posts to respect the free rate limit
        if "vt" in targets and not dry:
            time.sleep(publish._BATCH_THROTTLE)
    with _lock:
        _state["last_scan"] = R_now()
        _state["skipped"] += max(0, len(drafts) - len(todo))
    return {"eligible": len(todo), "published_now": sum(1 for r in results if r.get("ok")),
            "dry_run": dry, "results": results}


def R_now() -> str:
    from .report import now_utc
    return now_utc()


def _loop(interval: int) -> None:
    with _lock:
        _state["running"] = True
        _state["enabled"] = True
    try:
        while not _stop.wait(1):
            scan_once(dry=False)
            if _stop.wait(interval):
                break
    finally:
        with _lock:
            _state["running"] = False


def start() -> dict:
    global _thread
    if _thread and _thread.is_alive():
        return {"already_running": True}
    _stop.clear()
    interval = settings()["interval"]
    _thread = threading.Thread(target=_loop, args=(interval,), daemon=True)
    _thread.start()
    return {"started": True, "interval": interval}


def stop() -> dict:
    _stop.set()
    with _lock:
        _state["enabled"] = False
    return {"stopped": True}


def maybe_autostart() -> None:
    """Called by the web server on boot; starts the daemon if opted in."""
    if os.environ.get("ARGUS_AUTOPUBLISH", "") == "1":
        start()
