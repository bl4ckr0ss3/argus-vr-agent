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


_DRAFT_CACHE: dict = {}   # dir_name -> (findings_mtime, entry-without-status)


def list_drafts(limit: int = 0) -> list[dict]:
    """Rich review-queue listing for the Findings panel: verdict, confidence,
    signals, the tweet draft, status, the safety verdict and a link to the
    finding's 0xblack.dev report. Newest first; `limit` caps the count (0=all).

    findings.json is immutable after creation, so its parse (+ family lookup) is
    cached per draft; only the tiny STATUS file is re-read each call. This keeps
    the panel/Autopilot fast even with thousands of accumulated drafts."""
    out = []
    if not REVIEW_DIR.exists():
        return out
    from . import site_publish
    dirs = sorted((d for d in REVIEW_DIR.iterdir() if d.is_dir()), reverse=True)
    if limit and limit > 0:
        dirs = dirs[:limit]
    for d in dirs:
        fj = d / "findings.json"
        try:
            mt = fj.stat().st_mtime if fj.exists() else 0
        except OSError:
            mt = 0
        cached = _DRAFT_CACHE.get(d.name)
        if cached and cached[0] == mt:
            entry = dict(cached[1])
        else:
            info = load_draft(str(d))
            struct = info.get("struct", {}) or {}
            sha = struct.get("sha256") or ""
            entry = {
                "id": d.name,
                "sample": struct.get("sample"), "sha256": sha,
                "family": _family(struct),
                "verdict": struct.get("verdict"), "confidence": struct.get("confidence"),
                "signals": struct.get("signals", []),
                "attack": [t.get("id") for t in struct.get("attack", [])],
                "vt": (struct.get("vt") or {}).get("summary"),
                "vt_url": f"https://www.virustotal.com/gui/file/{sha}" if len(sha) == 64 else None,
                "report_url": site_publish.analysis_url(sha),
                "tweet": info.get("tweet"),
                "safety": safety_reason(struct),
            }
            _DRAFT_CACHE[d.name] = (mt, entry)
            entry = dict(entry)
        # status changes on publish — always read the tiny STATUS file fresh
        stf = d / "STATUS"
        try:
            entry["status"] = stf.read_text(encoding="utf-8").strip() if stf.exists() else "unknown"
        except OSError:
            entry["status"] = "unknown"
        out.append(entry)
    # evict cache entries for drafts that no longer exist
    if len(_DRAFT_CACHE) > len(dirs) + 2000:
        keep = {d.name for d in dirs}
        for k in [k for k in _DRAFT_CACHE if k not in keep]:
            _DRAFT_CACHE.pop(k, None)
    return out


def approve(draft: str) -> dict:
    d = _resolve(draft)
    if not d.is_dir():
        return {"error": f"no such draft: {draft}"}
    (d / "STATUS").write_text("approved\n", encoding="utf-8")
    return {"ok": True, "dir": str(d), "status": "approved"}


def _days_since(iso_date: str) -> int:
    """Days since an ISO date string. Returns 999 on parse failure."""
    try:
        from datetime import datetime
        dt = datetime.fromisoformat(iso_date)
        return (datetime.now() - dt).days
    except Exception:
        return 999


def safety_reason(struct: dict) -> str | None:
    """Why this finding must NOT be auto-published (None = clear to publish).

    A 0/70 VT result blocks AUTO-publish by default. Set ARGUS_PUBLISH_UNDETECTED=1
    to let ARGUS auto-publish a *fresh* (<30d) 0/70 as likely-undetected malware;
    even then the human can always push a blocked finding manually from the panel.
    """
    vt = struct.get("vt") or {}
    conflict = (struct.get("vt_conflict") or "").lower()
    if "false positive" in conflict:
        return "VirusTotal contradicts the heuristic (likely false positive)"

    if vt.get("found") and vt.get("total", 0) >= 20 and vt.get("malicious", 0) == 0:
        first_seen = vt.get("first_seen") or ""
        age_days = _days_since(first_seen) if first_seen else None
        age_txt = f" (sample is {age_days}d old)" if age_days is not None else ""
        # A 0/70 on a brand-new sample IS plausibly undetected malware — but
        # auto-voting "malicious" on VT when VT itself shows it clean is exactly
        # where a false positive burns our reputation publicly. So this bypass is
        # OPT-IN (ARGUS_PUBLISH_UNDETECTED=1); otherwise a 0/70 stays blocked for
        # AUTO-publish and the human can still push it manually from the panel.
        if os.environ.get("ARGUS_PUBLISH_UNDETECTED", "").strip() == "1" and age_days is not None and age_days < 30:
            struct["vt_note"] = f"undetected (0/{vt['total']}) — fresh sample ({age_days}d old)"
            return None
        return f"VirusTotal shows 0/{vt['total']} detections{age_txt}"

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


def _http_post_retry(url: str, headers: dict, body: bytes, tries: int = 3) -> tuple[int, str]:
    """POST with backoff on 429 / 5xx — VT's free API is rate-limited, so a burst
    would otherwise drop comments. Waits 15s, 30s between attempts."""
    last = None
    for i in range(tries):
        try:
            return _http_post(url, headers, body)
        except urllib.error.HTTPError as e:
            last = e
            if e.code in (429, 500, 502, 503) and i < tries - 1:
                time.sleep(15 * (i + 1))
                continue
            raise
    if last:
        raise last
    raise RuntimeError("no attempt made")


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


def _uniq(seq):
    seen, out = set(), []
    for x in seq or []:
        s = str(x).strip()
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _short(s, n: int = 90) -> str:
    """Truncate a token so VT doesn't reject the comment ('too long word' — VT
    caps individual word length; long paths/hashes and the compact JSON hit it)."""
    s = str(s)
    return s if len(s) <= n else s[:n - 1] + "…"


def _cap_ioc(ioc: dict, n: int = 68) -> dict:
    out = {}
    for k, v in ioc.items():
        if isinstance(v, list):
            out[k] = [_short(x, n) for x in v]
        elif isinstance(v, str):
            out[k] = _short(v, n)
        else:
            out[k] = v
    return out


def _tagify(s: str) -> str:
    """A safe #hashtag from an arbitrary label."""
    import re
    t = re.sub(r"[^0-9A-Za-z]+", "", str(s))
    return ("#" + t) if t else ""


def _finding_tags(struct: dict, view_family: str | None) -> list[str]:
    tags = ["#malware", "#DFIR", "#threatintel", "#malwareanalysis", "#ARGUS"]
    ext = (struct.get("sample") or "").rsplit(".", 1)
    if len(ext) == 2 and len(ext[1]) <= 5:
        tags.append("#" + ext[1].lower())
    sigmap = {"packed": "#packed", "executable-drop": "#dropper",
              "child-processes": "#processinjection", "network": "#C2",
              "persistence": "#persistence"}
    for s in struct.get("signals") or []:
        if s in sigmap:
            tags.append(sigmap[s])
    for t in struct.get("attack") or []:
        if t.get("id"):
            tags.append("#" + str(t["id"]).replace(".", "_"))
    for y in (struct.get("yara") or [])[:4]:
        tt = _tagify(y)
        if tt:
            tags.append(tt)
    if view_family and " " not in view_family and "," not in view_family:
        tags.append(_tagify(view_family))
    # dedup, keep order
    seen, out = set(), []
    for t in tags:
        if t and t.lower() not in seen:
            seen.add(t.lower())
            out.append(t)
    return out


# Map common YARA rule-name fragments -> a clean family label (fallback when
# MalwareBazaar didn't give us a signature).
_YARA_FAMILIES = ("asyncrat", "redline", "formbook", "agenttesla", "remcos",
                  "lokibot", "njrat", "quasar", "xworm", "amadey", "stealc",
                  "lumma", "vidar", "raccoon", "snakekeylogger", "nanocore",
                  "danabot", "smokeloader", "cobaltstrike", "salatstealer")


def _family(struct: dict) -> str | None:
    """Best-effort malware family: explicit field -> MalwareBazaar signature
    (recorded at fetch) -> a YARA-derived name. None if genuinely unknown."""
    if struct.get("family"):
        return struct["family"]
    sha = (struct.get("sha256") or "").strip()
    if len(sha) == 64:
        try:
            from .intel.malwarebazaar import family_for
            fam = family_for(sha)
            if fam:
                return fam
        except Exception:
            pass
    for y in struct.get("yara") or []:
        low = str(y).lower()
        for fam in _YARA_FAMILIES:
            if fam in low:
                return fam.capitalize()
    return None


def _ioc_json(struct: dict, family: str | None) -> dict:
    """A compact, publishable IOC object for defenders to copy-paste."""
    obj = {
        "sha256": struct.get("sha256"),
        "family": family,
        "verdict": struct.get("verdict"),
        "confidence": struct.get("confidence"),
        "signals": struct.get("signals") or [],
        "attack": [t.get("id") for t in (struct.get("attack") or [])],
        "network": _uniq(struct.get("net"))[:12],
        "dropped": _uniq(struct.get("staged_payloads"))[:12],
        "children": _uniq(struct.get("spawned"))[:12],
    }
    return {k: v for k, v in obj.items() if v}


def build_vt_comment(struct: dict) -> str:
    """A structured, MalwareBazaar-style VT comment: bold labelled fields, a
    MalwareBazaar link, a link to the full 0xblack.dev analysis, a concise
    behavioural summary and hashtags. Uses markdown the VT community renderer
    understands (**bold**, auto-linked URLs, #tags)."""
    from . import site_publish
    verdict = struct.get("verdict", "inconclusive")
    conf = struct.get("confidence", 0) or 0
    sha = (struct.get("sha256") or "").strip()
    sample = struct.get("sample") or (sha[:16] if sha else "sample")
    head = _VERDICT_LINE.get(verdict, verdict.upper())

    ext = sample.rsplit(".", 1)
    ftype = ext[1].lower() if len(ext) == 2 and len(ext[1]) <= 5 else "bin"

    family = _family(struct)

    L: list[str] = []
    L.append("**ARGUS Malware Analysis**")
    L.append("")
    L.append(f"**Filename:** {sample}")
    L.append(f"**Verdict:** {head} — confidence {conf}% ({_CONF_BAND(conf)})")
    L.append(f"**File Type:** {ftype}")
    if family:
        L.append(f"**Family / Signature:** {family}")
    L.append(f"**SHA-256:** {sha}")
    L.append(f"**MalwareBazaar:** https://bazaar.abuse.ch/sample/{sha}")
    url = site_publish.analysis_url(sha)
    if url:
        L.append(f"**Full Analysis:** {url}")

    if struct.get("analyst_summary"):
        L.append("")
        L.append("**Analysis:** " + struct["analyst_summary"])

    # concise behaviour block
    spawned = _uniq(struct.get("spawned"))
    drops = _uniq(struct.get("staged_payloads"))
    net = _uniq(struct.get("net"))
    persistence = _uniq(struct.get("persistence"))
    beh = []
    if persistence:
        beh.append("- Persistence: " + "; ".join(_short(x) for x in persistence[:4]))
    if spawned:
        beh.append("- Child processes: " + "; ".join(_short(x) for x in spawned[:4]))
    if drops:
        beh.append("- Dropped files: " + "; ".join(_short(x) for x in drops[:4]))
    if net:
        beh.append("- Network: " + ", ".join(_short(x) for x in net[:6]))
    if struct.get("packed"):
        pk = struct.get("packer")
        if isinstance(pk, dict):
            pk = pk.get("packer") or "detected"
        ent = struct.get("entropy")
        beh.append(f"- Packing: {pk}" + (f" (entropy {ent})" if ent else ""))
    if beh:
        L.append("")
        L.append("**Observed behaviour:**")
        L.extend(beh)

    attack = struct.get("attack") or []
    if attack:
        L.append("")
        L.append("**MITRE ATT&CK:** " + ", ".join(
            f"{t.get('id')} {t.get('name','')}".strip() for t in attack[:8]))

    # defanged IOCs
    try:
        from . import ioc as _ioc
        own = sha.lower()
        flat = []
        for cat, vals in (_ioc.extract_from(struct, struct.get("static")) or {}).items():
            for v in vals[:6]:
                low = str(v).lower()
                if low == own or low in _IOC_DENY:
                    continue
                flat.append(_ioc.defang(v, _ioc._KIND.get(cat, cat)))
        if flat:
            L.append("")
            L.append("**IOCs (defanged):** " + ", ".join(_short(x) for x in flat[:12]))
    except Exception:
        pass

    # publishable JSON IOC block — copy-paste for defenders / SIEM. INDENTED
    # (not compact) + long values truncated, so VT never sees a "too long word".
    ioc = _ioc_json(struct, family)
    if ioc:
        L.append("")
        L.append("**IOCs (JSON):**")
        L.append("```json")
        L.append(json.dumps(_cap_ioc(ioc), indent=2))
        L.append("```")

    L.append("")
    L.append("**Tags:**")
    L.append(" ".join(_finding_tags(struct, family)))
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
    # Community vote cast alongside the comment: malicious (-1) for a suspicious
    # verdict, harmless (+1) for benign. Inconclusive casts no vote.
    vote = {"suspicious": "malicious", "benign": "harmless"}.get(struct.get("verdict"))
    if dry_run:
        detail = f"would comment on {sha[:12]} ({len(text)} chars)"
        if vote:
            detail += f" + vote '{vote}'"
        return {"target": "vt", "ok": True, "dry_run": True, "detail": f"{detail}:\n{text}"}
    headers = {"x-apikey": key, "Content-Type": "application/json"}
    base = config.VT_API.rstrip("/")
    try:
        code, resp = _http_post_retry(f"{base}/files/{sha}/comments", headers,
                                json.dumps({"data": {"type": "comment", "attributes": {"text": text[:4000]}}}).encode())
        vmsg = ""
        if vote:
            try:
                vc, _ = _http_post(f"{base}/files/{sha}/votes", headers,
                                   json.dumps({"data": {"type": "vote", "attributes": {"verdict": vote}}}).encode())
                vmsg = f", vote {vote} HTTP {vc}"
            except urllib.error.HTTPError as e:
                vmsg = f", vote {vote} HTTP {e.code}"  # e.g. 409 if already voted
            except Exception as e:
                vmsg = f", vote {vote} failed: {e}"
        return {"target": "vt", "ok": code in (200, 201), "detail": f"comment HTTP {code}{vmsg}"}
    except urllib.error.HTTPError as e:
        return {"target": "vt", "ok": False, "detail": f"HTTP {e.code} {e.read().decode('utf-8','ignore')[:160]}"}
    except Exception as e:
        return {"target": "vt", "ok": False, "detail": str(e)}


_ADAPTERS = {"twitter": "post_twitter", "linkedin": "post_linkedin", "vt": "post_vt_comment"}


def build_tweet(struct: dict) -> str:
    """A shareable tweet that LINKS the 0xblack.dev report, so X renders its
    OpenGraph card. Kept under 280 chars."""
    from . import site_publish
    verdict = struct.get("verdict", "inconclusive")
    conf = struct.get("confidence", 0) or 0
    sample = struct.get("sample") or (struct.get("sha256", "")[:16])
    if len(sample) > 46:
        sample = sample[:43] + "..."
    label = {"suspicious": "SUSPICIOUS", "benign": "BENIGN"}.get(verdict, verdict.upper())
    url = site_publish.analysis_url(struct.get("sha256", ""))
    head = f"New malware finding: {sample} — {label} ({conf}%). Analysis by ARGUS."
    parts = [head] + ([url] if url else []) + ["#malware #DFIR #threatintel"]
    return " ".join(parts)[:280]


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
    tweet = build_tweet(struct)  # links the 0xblack.dev report for a card preview
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
_BATCH_THROTTLE = float(os.environ.get("ARGUS_VT_THROTTLE", "8"))

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
