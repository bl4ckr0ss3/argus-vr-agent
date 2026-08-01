"""Tests for the human-gated publish pipeline.

The safety machinery is the whole point, so it's what we lock down: no publish
without approval, no publish of a VT-contradicted / low-confidence finding
(unless forced), dry-run touches no network, and a real publish flips the draft
to 'published'. No live network here.
"""
import json

import argus.publish as pub


def _mkdraft(tmp_path, struct, status="pending-review", tweet="tweet text"):
    d = tmp_path / "draft1"
    d.mkdir()
    (d / "findings.json").write_text(json.dumps(struct), encoding="utf-8")
    (d / "STATUS").write_text(status + "\n", encoding="utf-8")
    (d / "tweet.txt").write_text(tweet, encoding="utf-8")
    (d / "writeup.md").write_text("# writeup", encoding="utf-8")
    return d


def test_safety_reason():
    # a solid suspicious finding is clear to publish
    assert pub.safety_reason({"verdict": "suspicious", "confidence": 90, "signals": ["network"]}) is None
    # VT-flagged false positive is refused
    assert "false positive" in pub.safety_reason(
        {"verdict": "suspicious", "vt_conflict": "... likely false positive"}).lower()
    # a benign verdict is not a malware finding
    assert pub.safety_reason({"verdict": "benign", "confidence": 85})
    # low confidence is refused
    assert pub.safety_reason({"verdict": "suspicious", "confidence": 40, "signals": ["x"]})
    # 0 VT detections is refused
    assert pub.safety_reason(
        {"verdict": "suspicious", "confidence": 90, "vt": {"found": True, "total": 72, "malicious": 0}})


def test_refuses_unapproved(tmp_path):
    d = _mkdraft(tmp_path, {"verdict": "suspicious", "confidence": 90, "signals": ["network"]})
    r = pub.publish(str(d), ["vt"])
    assert not r["ok"] and "not approved" in r["blocked"]


def test_refuses_unsafe_unless_forced(tmp_path):
    d = _mkdraft(tmp_path, {"verdict": "benign", "confidence": 85}, status="approved")
    r = pub.publish(str(d), ["twitter"])
    assert not r["ok"] and "safety refusal" in r["blocked"]
    r2 = pub.publish(str(d), ["twitter"], force=True)
    assert r2["ok"] and r2["safety_override"]


def test_dryrun_touches_no_network(tmp_path, monkeypatch):
    for k in ("TWITTER_API_KEY", "LINKEDIN_ACCESS_TOKEN"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(pub.config, "VT_API_KEY", "")
    d = _mkdraft(tmp_path, {"verdict": "suspicious", "confidence": 90,
                            "signals": ["network"], "sha256": "a" * 64}, status="approved")
    r = pub.publish(str(d), ["vt", "twitter", "linkedin"])
    assert r["ok"] and r["dry_run"]
    assert all(res.get("skipped") for res in r["results"])  # no creds -> all skipped, no calls


def test_real_publish_marks_published(tmp_path, monkeypatch):
    monkeypatch.setattr(pub, "post_vt_comment",
                        lambda struct, dry_run=True: {"target": "vt", "ok": True, "detail": "HTTP 200"})
    d = _mkdraft(tmp_path, {"verdict": "suspicious", "confidence": 90,
                            "signals": ["network"], "sha256": "a" * 64}, status="approved")
    r = pub.publish(str(d), ["vt"], confirm=True)
    assert r["ok"] and not r["dry_run"]
    assert (d / "STATUS").read_text().strip() == "published"


def test_oauth1_header_builds():
    h = pub._oauth1_header("POST", "https://api.twitter.com/2/tweets",
                           {"api_key": "k", "api_secret": "s",
                            "access_token": "t", "access_secret": "ts"})
    assert h.startswith("OAuth ") and "oauth_signature" in h
