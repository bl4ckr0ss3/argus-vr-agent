"""Tests for the severity classification engine (argus.severity)."""
from argus.severity import classify_severity, format_severity_banner


def test_genuine_critical_classified_critical():
    """A fully-evidenced arbitrary-kernel-write must be CRITICAL, not downgraded."""
    r = classify_severity(
        title="Arbitrary kernel write via unchecked IOCTL size",
        cwe="CWE-787",
        hypothesis=(
            "IOCTL copies user-supplied size without bounds check yielding arbitrary "
            "kernel write; unauthenticated standard user via GENERIC_READ handle; "
            "default on all Windows 11; then overwrite token and spawn cmd as SYSTEM; "
            "bypasses kCFG via data-section pointer"
        ),
        evidence=(
            "Disassembly: memcpy(kernel_buf, user_buf, user_size) no ProbeForWrite. "
            "BSOD with controlled RIP. token steal works."
        ),
    )
    assert r["is_critical"] is True
    assert r["severity"] == "critical"
    assert r["cvss_estimate"] >= 9.0


def test_overclaim_downgraded():
    """Hedged/conditional language must be downgraded, never CRITICAL."""
    r = classify_severity(
        title="potential LPE maybe critical",
        cwe="",
        hypothesis="might be exploitable if attacker could trigger the race",
        evidence="static analysis only",
    )
    assert r["is_critical"] is False
    assert r["severity"] == "medium"
    assert r["flags"], "expected overclaim flags to be recorded"


def test_missing_evidence_downgraded():
    """A primitive with thin evidence must stay HIGH, not CRITICAL."""
    r = classify_severity(
        title="command injection in hostname field",
        cwe="CWE-78",
        hypothesis="the hostname param reaches system()",
        evidence="",
    )
    assert r["is_critical"] is False
    assert r["severity"] in ("medium", "high")
    assert r["all_critical_evidence_passed"] is False


def test_banner_mentions_severity():
    """format_severity_banner should surface the verdict."""
    r = classify_severity(
        title="SSRF to cloud metadata",
        cwe="CWE-918",
        hypothesis=(
            "callback_url field fetches arbitrary URL; unauthenticated remote; "
            "hits 169.254.169.254 IAM credentials; chain to assume role;"
        ),
        evidence="received IAM token JSON",
    )
    banner = format_severity_banner(r)
    assert r["severity"].upper() in banner
