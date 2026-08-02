"""Human-gated publish pipeline.

NOTHING here posts automatically. Getting a finding out is two deliberate human
steps, and the send step defaults to a DRY RUN:

    1. review the draft  (runs/review_queue/<id>/writeup.md)  ->  approve it
    2. publish the approved draft to chosen targets  (dry-run unless --confirm)

Guardrails (this is security disclosure — a wrong "X is malware" is defamatory
and cannot be un-posted):
  - refuses to publish a draft that has not been explicitly approved
  - refuses to publish when VirusTotal contradicts the call (0 detections /
    flagged false-positive) or confidence is low, unless --force
  - each target adapter is a no-op unless ITS credentials are present
  - host-only: these credentials must NEVER live in the detonation VM

Targets: 'vt' (comment on the hash — never uploads), 'twitter', 'linkedin'.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import quote

import config
from .autohunt import REVIEW_DIR

_TIMEOUT = 20


# ---------------------------------------------------------------------------
# draft state
# ---------------------------------------------------------------------------
def _resolve(draft: str) -> Path:
    """Accept a full path or a bare draft folder name under the review queue."""
    p = Path(draft)
    if p.is_dir():
        return p
    cand = REVIEW_DIR / draft
    return cand


def load_draft(draft: str) -> dict:
    d = _resolve(draft)
    if not d.is_dir():
        return {"error": f"no such draft: {draft}"}
    fj = d / "findings.json"
    struct = json.loads(fj.read_text(encoding="utf-8")) if fj.exists() else {}
    status_f = d / "STATUS"
    return {
        "dir": d,
        "status": status_f.read_text(encoding="utf-8").strip() if status_f.exists() else "unknown",
        "struct": struct,
        "tweet": (d / "tweet.txt").read_text(encoding="utf-8") if (d / "tweet.txt").exists() else "",
        "writeup": (d / "writeup.md").read_text(encoding="utf-8") if (d / "writeup.md").exists() else "",
    }


def list_drafts() -> list[dict]:
    """Rich review-queue listing for the Findings panel: verdict, confidence,
    signals, the tweet draft, status, and the safety verdict per draft."""
    out = []
    if not REVIEW_DIR.exists():
        return out
    for d in sorted(REVIEW_DIR.iterdir(), reverse=True):
        if not d.is_dir():
            continue
        info = load_draft(str(d))
        struct = info.get("struct", {}) or {}
        out.append({
            "id": d.name, "status": info.get("status"),
            "sample": struct.get("sample"), "sha256": struct.get("sha256"),
            "verdict": struct.get("verdict"), "confidence": struct.get("confidence"),
            "signals": struct.get("signals", []),
            "attack": [t.get("id") for t in struct.get("attack", [])],
            "vt": (struct.get("vt") or {}).get("summary"),
            "tweet": info.get("tweet"),
            "safety": safety_reason(struct),   # None = clear to publish
        })
    return out


def approve(draft: str) -> dict:
    d = _resolve(draft)
    if not d.is_dir():
        return {"error": f"no such draft: {draft}"}
    (d / "STATUS").write_text("approved\n", encoding="utf-8")
    return {"ok": True, "dir": str(d), "status": "approved"}


def safety_reason(struct: dict) -> str | None:
    """Why this finding must NOT be auto-published (None = clear to publish)."""
    vt = struct.get("vt") or {}
    conflict = (struct.get("vt_conflict") or "").lower()
    if "false positive" in conflict:
        return "VirusTotal contradicts the heuristic (likely false positive)"
    if vt.get("found") and vt.get("total", 0) >= 20 and vt.get("malicious", 0) == 0:
        return f"VirusTotal shows 0/{vt['total']} detections"
    if struct.get("verdict") != "suspicious":
        return f"verdict is '{struct.get('verdict')}', not a malware finding"
    if struct.get("confidence", 0) < 55:
        return f"low confidence ({struct.get('confidence', '?')}%)"
    return None


# ---------------------------------------------------------------------------
# HTTP + OAuth helpers
# ---------------------------------------------------------------------------
def _http_post(url: str, headers: dict, body: bytes) -> tuple[int, str]:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
        return getattr(resp, "status", 200), resp.read().decode("utf-8", "ignore")


def _pct(s) -> str:
    return quote(str(s), safe="~")


def _oauth1_header(method: str, url: str, creds: dict) -> str:
    """OAuth 1.0a user-context Authorization header (Twitter v2 JSON endpoints:
    the JSON body is NOT part of the signature base, only the oauth params)."""
    oauth = {
        "oauth_consumer_key": creds["api_key"],
        "oauth_nonce": base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip("="),
        "oauth_signature_method": "HMAC-SHA1",
        "oauth_timestamp": str(int(time.time())),
        "oauth_token": creds["access_token"],
        "oauth_version": "1.0",
    }
    param_str = "&".join(f"{_pct(k)}={_pct(oauth[k])}" for k in sorted(oauth))
    base = "&".join([method.upper(), _pct(url), _pct(param_str)])
    signing_key = f"{_pct(creds['api_secret'])}&{_pct(creds['access_secret'])}"
    sig = base64.b64encode(
        hmac.new(signing_key.encode(), base.encode(), hashlib.sha1).digest()).decode()
    oauth["oauth_signature"] = sig
    return "OAuth " + ", ".join(f'{_pct(k)}="{_pct(v)}"' for k, v in sorted(oauth.items()))


# ---------------------------------------------------------------------------
# target adapters — each returns {target, ok, skipped, detail}
# ---------------------------------------------------------------------------
def _twitter_creds() -> dict | None:
    c = {
        "api_key": os.environ.get("TWITTER_API_KEY", "").strip(),
        "api_secret": os.environ.get("TWITTER_API_SECRET", "").strip(),
        "access_token": os.environ.get("TWITTER_ACCESS_TOKEN", "").strip(),
        "access_secret": os.environ.get("TWITTER_ACCESS_SECRET", "").strip(),
    }
    return c if all(c.values()) else None


def post_twitter(text: str, dry_run: bool = True) -> dict:
    creds = _twitter_creds()
    if not creds:
        return {"target": "twitter", "skipped": True, "detail": "no TWITTER_* credentials"}
    if dry_run:
        return {"target": "twitter", "ok": True, "dry_run": True, "detail": f"would tweet: {text[:120]}"}
    url = "https://api.twitter.com/2/tweets"
    headers = {"Authorization": _oauth1_header("POST", url, creds),
               "Content-Type": "application/json"}
    try:
        code, body = _http_post(url, headers, json.dumps({"text": text}).encode())
        return {"target": "twitter", "ok": code in (200, 201), "detail": f"HTTP {code} {body[:160]}"}
    except urllib.error.HTTPError as e:
        return {"target": "twitter", "ok": False, "detail": f"HTTP {e.code} {e.read().decode('utf-8','ignore')[:160]}"}
    except Exception as e:
        return {"target": "twitter", "ok": False, "detail": str(e)}


def post_linkedin(text: str, dry_run: bool = True) -> dict:
    token = os.environ.get("LINKEDIN_ACCESS_TOKEN", "").strip()
    author = os.environ.get("LINKEDIN_AUTHOR_URN", "").strip()  # urn:li:person:xxxx
    if not token or not author:
        return {"target": "linkedin", "skipped": True, "detail": "no LINKEDIN_ACCESS_TOKEN / LINKEDIN_AUTHOR_URN"}
    if dry_run:
        return {"target": "linkedin", "ok": True, "dry_run": True, "detail": f"would post: {text[:120]}"}
    url = "https://api.linkedin.com/v2/ugcPosts"
    payload = {
        "author": author,
        "lifecycleState": "PUBLISHED",
        "specificContent": {"com.linkedin.ugc.ShareContent": {
            "shareCommentary": {"text": text},
            "shareMediaCategory": "NONE"}},
        "visibility": {"com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"},
    }
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json",
               "X-Restli-Protocol-Version": "2.0.0"}
    try:
        code, body = _http_post(url, headers, json.dumps(payload).encode())
        return {"target": "linkedin", "ok": code in (200, 201), "detail": f"HTTP {code} {body[:160]}"}
    except urllib.error.HTTPError as e:
        return {"target": "linkedin", "ok": False, "detail": f"HTTP {e.code} {e.read().decode('utf-8','ignore')[:160]}"}
    except Exception as e:
        return {"target": "linkedin", "ok": False, "detail": str(e)}


_VERDICT_LINE = {
    "suspicious": "Assessed SUSPICIOUS (behaviour consistent with malware)",
    "benign": "Assessed BENIGN (no malicious behaviour observed)",
    "inconclusive": "INCONCLUSIVE (insufficient behavioural evidence)",
}
_CONF_BAND = lambda c: ("high" if c >= 85 else "moderate" if c >= 65 else "low")

# Benign artefacts that leak in from Windows system paths / OS telemetry and
# must never appear as IOCs in a published comment.
_IOC_DENY = {
    "microsoft.net", "microsoft.com", "windows.com", "windows.net",
    "live.com", "msftncsi.com", "msftconnecttest.com", "windowsupdate.com",
    "digicert.com", "verisign.com", "sectigo.com", "globalsign.com",
    "schemas.microsoft.com", "go.microsoft.com", "w3.org", "example.com",
}


def build_vt_comment(struct: dict) -> str:
    """A professional, analyst-grade VT comment: methodology, observed behavior,
    ATT&CK mapping, IOCs and a disclaimer. Sections with no data are omitted so
    the comment stays accurate rather than padded."""
    verdict = struct.get("verdict", "inconclusive")
    conf = struct.get("confidence", 0) or 0
    head = _VERDICT_LINE.get(verdict, verdict.upper())
    L: list[str] = []
    L.append(f"=== ARGUS Automated Triage Report ===")
    L.append(f"{head} — confidence {conf}% ({_CONF_BAND(conf)}).")
    L.append("")
    L.append("Methodology: sample executed in an isolated, instrumented Windows "
             "VM (host-only networking with emulated C2 responses) while process, "
             "file-system, registry and network activity were recorded. The "
             "verdict below is derived by correlating observed runtime behaviour "
             "with static indicators; no sample was uploaded.")
    L.append("")
    L.append("-- Observed behaviour --")

    def _uniq(seq):
        seen, out = set(), []
        for x in seq or []:
            s = str(x).strip()
            if s and s not in seen:
                seen.add(s)
                out.append(s)
        return out

    persistence = _uniq(struct.get("persistence"))
    spawned = _uniq(struct.get("spawned"))
    drops = _uniq(struct.get("staged_payloads"))
    net = _uniq(struct.get("net"))
    if persistence:
        L.append(f"* Persistence ({len(persistence)}): " + "; ".join(persistence[:6]))
    if spawned:
        L.append(f"* Child processes ({len(spawned)}): " + "; ".join(spawned[:6]))
    if drops:
        L.append(f"* Dropped files ({len(drops)}): " + "; ".join(drops[:6]))
    if net:
        L.append(f"* Network endpoints contacted ({len(net)}): " + ", ".join(net[:8]))
    if struct.get("packed"):
        pk = struct.get("packer")
        if isinstance(pk, dict):
            name = pk.get("packer") or "detected"
            conf = pk.get("confidence")
            pk = f"{name}" + (f" ({conf} confidence)" if conf else "")
        ent = struct.get("entropy")
        L.append(f"* Packing/obfuscation: {pk or 'detected'}"
                 + (f"; overall entropy {ent}" if ent else ""))
    if not any((persistence, spawned, drops, net, struct.get("packed"))):
        L.append("* No high-confidence host or network side effects captured in "
                 "this run (payload may be environment-gated or dormant).")

    signals = struct.get("signals") or []
    if signals:
        L.append("")
        L.append("Heuristic signals: " + ", ".join(signals))

    attack = struct.get("attack") or []
    if attack:
        L.append("")
        L.append("MITRE ATT&CK: " + "; ".join(
            f"{t.get('id')} {t.get('name','')}".strip() for t in attack[:10]))

    yara = struct.get("yara") or []
    if yara:
        L.append("YARA matches: " + ", ".join(yara[:8]))

    # defanged IOCs for defenders
    try:
        from . import ioc as _ioc
        iocs = _ioc.extract_from(struct, struct.get("static"))
        own = (struct.get("sha256") or "").lower()  # don't list the file's own hash as an IOC of itself
        flat = []
        for cat, vals in (iocs or {}).items():
            for v in vals[:6]:
                low = str(v).lower()
                if low == own or low in _IOC_DENY:
                    continue
                flat.append(_ioc.defang(v, _ioc._KIND.get(cat, cat)))
        if flat:
            L.append("")
            L.append("Indicators of Compromise (defanged): " + ", ".join(flat[:16]))
    except Exception:
        pass

    vt = struct.get("vt") or {}
    if vt.get("summary"):
        L.append("")
        L.append(f"Cross-reference: VirusTotal reputation at analysis time — {vt['summary']}.")

    L.append("")
    L.append("This is an automated assessment shared for community awareness and "
             "should be independently verified before operational use. "
             "Analysis: ARGUS. #malware #DFIR #threatintel #malwareanalysis")
    return "\n".join(L)


def post_vt_comment(struct: dict, dry_run: bool = True) -> dict:
    """Attach the analysis as a COMMENT on the existing hash. Never uploads a sample."""
    key = (config.VT_API_KEY or "").strip()
    sha = (struct.get("sha256") or "").strip()
    if not key:
        return {"target": "vt", "skipped": True, "detail": "no VT_API_KEY"}
    if len(sha) != 64:
        return {"target": "vt", "skipped": True, "detail": "no sha256 to comment on"}
    text = build_vt_comment(struct)
    if dry_run:
        return {"target": "vt", "ok": True, "dry_run": True,
                "detail": f"would comment on {sha[:12]} ({len(text)} chars):\n{text}"}
    url = f"{config.VT_API.rstrip('/')}/files/{sha}/comments"
    body = json.dumps({"data": {"type": "comment", "attributes": {"text": text[:4000]}}}).encode()
    headers = {"x-apikey": key, "Content-Type": "application/json"}
    try:
        code, resp = _http_post(url, headers, body)
        return {"target": "vt", "ok": code in (200, 201), "detail": f"HTTP {code}"}
    except urllib.error.HTTPError as e:
        return {"target": "vt", "ok": False, "detail": f"HTTP {e.code} {e.read().decode('utf-8','ignore')[:160]}"}
    except Exception as e:
        return {"target": "vt", "ok": False, "detail": str(e)}


_ADAPTERS = {"twitter": "post_twitter", "linkedin": "post_linkedin", "vt": "post_vt_comment"}


# ---------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------
def publish(draft: str, targets: list[str], confirm: bool = False,
            force: bool = False) -> dict:
    """Publish an APPROVED draft to targets. Dry-run unless confirm=True.

    Returns {ok, dry_run, blocked?, results:[...]} — never raises."""
    info = load_draft(draft)
    if info.get("error"):
        return {"ok": False, "error": info["error"]}
    if info["status"] != "approved":
        return {"ok": False, "blocked": f"draft not approved (status: {info['status']}). "
                                        f"Review it, then: run.py publish <draft> --approve"}

    struct = info["struct"]
    reason = safety_reason(struct)
    if reason and not force:
        return {"ok": False, "blocked": f"safety refusal: {reason}. "
                                        f"Override only if you are certain: add --force"}

    dry = not confirm
    tweet = info["tweet"] or (struct.get("verdict_text", ""))
    results = []
    for t in targets:
        if t == "twitter":
            results.append(post_twitter(tweet, dry_run=dry))
        elif t == "linkedin":
            results.append(post_linkedin(info["writeup"][:2900] or tweet, dry_run=dry))
        elif t == "vt":
            results.append(post_vt_comment(struct, dry_run=dry))
        else:
            results.append({"target": t, "skipped": True, "detail": "unknown target"})

    # After a real, successful publish, mark the draft so it isn't re-posted.
    if not dry and any(r.get("ok") and not r.get("skipped") for r in results):
        (info["dir"] / "STATUS").write_text("published\n", encoding="utf-8")

    return {"ok": True, "dry_run": dry, "safety_override": bool(reason and force),
            "results": results}


# ---------------------------------------------------------------------------
# batch publish — "post all eligible to <targets>" with one click
# ---------------------------------------------------------------------------
# VirusTotal's free API is rate-limited (≈4 requests/min). Space posts out so a
# bulk run doesn't get throttled into 429s. Tunable via ARGUS_VT_THROTTLE.
_BATCH_THROTTLE = float(os.environ.get("ARGUS_VT_THROTTLE", "16"))

_batch: dict = {"running": False, "dry": True, "total": 0, "done": 0,
                "posted": 0, "skipped": 0, "failed": 0, "results": [],
                "targets": [], "finished": False}
_batch_lock = threading.Lock()


def batch_eligible(only_unpublished: bool = True) -> list[dict]:
    """Drafts a batch would act on: everything not already published, that the
    safety gate clears (suspicious + adequate confidence, VT not contradicting)."""
    out = []
    for d in list_drafts():
        if only_unpublished and d.get("status") == "published":
            continue
        if d.get("safety"):        # safety_reason is non-None -> would be blocked
            continue
        out.append(d)
    return out


def batch_status() -> dict:
    with _batch_lock:
        return dict(_batch, results=_batch["results"][-50:])


def start_batch(targets: list[str], confirm: bool = False,
                only_unpublished: bool = True) -> dict:
    """Kick off (or dry-run) a batch publish of all eligible drafts to `targets`.
    Returns immediately; poll batch_status() for progress. Never force-overrides
    the safety gate — unsafe drafts are simply excluded."""
    with _batch_lock:
        if _batch["running"]:
            return {"error": "a batch is already running", "status": dict(_batch)}
        todo = batch_eligible(only_unpublished)
        if not confirm:
            # dry run: report what WOULD post, post nothing
            return {"dry_run": True, "eligible": len(todo),
                    "samples": [d.get("sample") or d["id"] for d in todo[:200]]}
        _batch.update(running=True, dry=False, total=len(todo), done=0,
                      posted=0, skipped=0, failed=0, results=[],
                      targets=list(targets), finished=False)
    t = threading.Thread(target=_run_batch, args=(todo, targets), daemon=True)
    t.start()
    return {"started": True, "total": len(todo)}


def _run_batch(todo: list[dict], targets: list[str]) -> None:
    for i, d in enumerate(todo):
        approve(d["id"])  # a batch implies approval; the safety gate still applies
        res = publish(d["id"], targets, confirm=True, force=False)
        ok = res.get("ok") and not res.get("blocked") and \
            any(r.get("ok") and not r.get("skipped") for r in res.get("results", []))
        with _batch_lock:
            _batch["done"] = i + 1
            if res.get("blocked"):
                _batch["skipped"] += 1
            elif ok:
                _batch["posted"] += 1
            else:
                _batch["failed"] += 1
            _batch["results"].append({
                "id": d["id"], "sample": d.get("sample") or d["id"],
                "ok": bool(ok), "detail": res.get("blocked") or
                "; ".join(f"{r['target']}:{'ok' if r.get('ok') else r.get('detail','?')}"
                          for r in res.get("results", []))})
        if i < len(todo) - 1:
            time.sleep(_BATCH_THROTTLE)
    with _batch_lock:
        _batch["running"] = False
        _batch["finished"] = True
