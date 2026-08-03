"""VirusTotal hash-lookup enrichment (stdlib only).

ARGUS NEVER uploads a sample — this looks up the sample's SHA-256 against the
VirusTotal v3 API and folds the AV consensus into a detonation's findings. That
consensus is the strongest single defense against the heuristic's false
positives: if VT says 0/72, a "suspicious" heuristic call is probably a false
alarm; if VT says 55/72, a "benign" call deserves a second look.

Runs wherever the VT key lives — the HOST, during review — so the detonation VM
stays credential-free. Requires config.VT_API_KEY (free from virustotal.com);
degrades to a no-op when the key is absent so callers never have to branch.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

import config

_TIMEOUT = 20


def available() -> bool:
    return bool((config.VT_API_KEY or "").strip())


def lookup(sha256: str) -> dict:
    """Look up one hash. Returns a normalized dict; never raises.

    Keys: found, malicious, suspicious, harmless, undetected, total,
          reputation, names, threat_label, summary, error.
    """
    out = {"found": False, "malicious": 0, "suspicious": 0, "harmless": 0,
           "undetected": 0, "total": 0, "reputation": 0, "names": [],
           "threat_label": "", "first_seen": "", "summary": "", "error": None}
    key = (config.VT_API_KEY or "").strip()
    if not key:
        out["error"] = "no VT_API_KEY set"
        return out
    sha256 = (sha256 or "").strip()
    if len(sha256) != 64:
        out["error"] = f"not a sha256: {sha256[:16]}..."
        return out

    url = f"{config.VT_API.rstrip('/')}/files/{sha256}"
    req = urllib.request.Request(url, headers={"x-apikey": key})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            out["summary"] = "not seen on VirusTotal (0 submissions)"
        else:
            out["error"] = f"HTTP {e.code}"
        return out
    except (urllib.error.URLError, TimeoutError, ValueError) as e:
        out["error"] = str(e)
        return out

    attr = (data.get("data") or {}).get("attributes") or {}
    stats = attr.get("last_analysis_stats") or {}
    out["found"] = True
    out["malicious"] = int(stats.get("malicious", 0))
    out["suspicious"] = int(stats.get("suspicious", 0))
    out["harmless"] = int(stats.get("harmless", 0))
    out["undetected"] = int(stats.get("undetected", 0))
    out["total"] = sum(int(v) for v in stats.values() if isinstance(v, (int, float)))
    out["reputation"] = int(attr.get("reputation", 0))
    names = attr.get("names") or []
    out["names"] = names[:5]
    ptc = attr.get("popular_threat_classification") or {}
    out["threat_label"] = ptc.get("suggested_threat_label", "") or ""
    # first_submission_date is a Unix epoch; expose it as an ISO date so callers
    # can reason about sample freshness (a 0/70 on a brand-new sample is likely
    # undetected malware, not a false positive). Without this the freshness gates
    # in autohunt/publish always saw "age 999" and never fired.
    fsd = attr.get("first_submission_date")
    if fsd:
        try:
            from datetime import datetime, timezone
            out["first_seen"] = datetime.fromtimestamp(int(fsd), tz=timezone.utc).date().isoformat()
        except Exception:
            pass
    det = f"{out['malicious']}/{out['total']}" if out["total"] else "0/0"
    label = f" · {out['threat_label']}" if out["threat_label"] else ""
    out["summary"] = f"malicious {det}{label}"
    return out


def enrich(struct: dict) -> dict:
    """Attach a VT lookup to a findings struct and reconcile it with the verdict.

    Adds struct['vt'] and, on a clear heuristic/VT disagreement, sets
    struct['vt_conflict'] and nudges the confidence so a reviewer notices.
    A no-op (returns struct unchanged) when no VT key is configured.
    """
    if not available():
        return struct
    vt = lookup(struct.get("sha256", ""))
    struct["vt"] = vt
    if not vt.get("found") or vt.get("error"):
        return struct

    verdict = struct.get("verdict")
    mal = vt["malicious"]
    total = vt.get("total", 0)
    # Freshness: how old is the first VT submission? A brand-new sample showing
    # 0/N is EXPECTED (signatures haven't caught up) — that is undetected malware,
    # not a false positive. Only a STALE 0/N with no other signals is a likely FP.
    age_days = 999
    fsd = vt.get("first_seen") or ""
    if fsd:
        try:
            from datetime import datetime
            age_days = (datetime.now() - datetime.fromisoformat(fsd)).days
        except Exception:
            pass
    is_fresh = age_days < 30
    # Heuristic says clean but AV consensus says malicious -> flag loudly.
    if verdict in ("benign", "inconclusive") and mal >= 5:
        struct["vt_conflict"] = (f"heuristic '{verdict}' but VirusTotal flags "
                                 f"{mal}/{vt['total']} - re-examine")
        struct["confidence"] = max(struct.get("confidence", 0), 70)
        struct["confidence_label"] = "high" if struct["confidence"] >= 80 else "medium"
    # Heuristic says suspicious but nobody else agrees -> likely a false positive.
    # NOTE: ONLY for a STALE sample. A fresh (age<30d) 0/N is undetected malware,
    # so we don't cripple its confidence nor set the "false positive" conflict (that
    # would block the freshness-aware publish gate in publish.safety_reason).
    elif verdict == "suspicious" and total >= 20 and mal == 0 and not is_fresh:
        struct["vt_conflict"] = (f"heuristic 'suspicious' but VirusTotal is clean "
                                 f"(0/{total}) after {age_days}d - likely false positive")
        struct["confidence"] = min(struct.get("confidence", 100), 45)
        struct["confidence_label"] = "low"
    # Agreement raises confidence.
    elif verdict == "suspicious" and mal >= 5:
        struct["confidence"] = min(98, struct.get("confidence", 0) + 10)
        struct["confidence_label"] = "high" if struct["confidence"] >= 80 else "medium"
    # Fresh sample, suspicious verdict, 0/N: keep confidence as-is (undetected
    # malware). Don't set vt_conflict; record a neutral freshness note instead.
    elif verdict == "suspicious" and total >= 20 and mal == 0 and is_fresh:
        struct["vt_note"] = (f"undetected (0/{total}) - fresh sample ({age_days}d)"
                             if age_days != 999 else "undetected (0/N)")
    return struct
