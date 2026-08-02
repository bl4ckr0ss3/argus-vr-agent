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


def post_vt_comment(struct: dict, dry_run: bool = True) -> dict:
    """Attach the analysis as a COMMENT on the existing hash. Never uploads a sample."""
    key = (config.VT_API_KEY or "").strip()
    sha = (struct.get("sha256") or "").strip()
    if not key:
        return {"target": "vt", "skipped": True, "detail": "no VT_API_KEY"}
    if len(sha) != 64:
        return {"target": "vt", "skipped": True, "detail": "no sha256 to comment on"}
    signals = ", ".join(struct.get("signals", [])) or "n/a"
    text = (f"ARGUS dynamic analysis: {struct.get('verdict', '?')} "
            f"(confidence {struct.get('confidence', '?')}%). Indicators: {signals}. "
            f"ATT&CK: {', '.join(t['id'] for t in struct.get('attack', []))}. #DFIR")
    if dry_run:
        return {"target": "vt", "ok": True, "dry_run": True, "detail": f"would comment on {sha[:12]}: {text[:100]}"}
    url = f"{config.VT_API.rstrip('/')}/files/{sha}/comments"
    body = json.dumps({"data": {"type": "comment", "attributes": {"text": text[:600]}}}).encode()
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
