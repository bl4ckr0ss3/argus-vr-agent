"""Severity verification engine — raises ARGUS's precision on CRITICAL bugs.

Critical classification is a *claim*, not a fact. This module enforces a hard
evidence floor: a finding is only CRITICAL when it passes a structured checklist
of proof requirements. Everything else is downgraded to HIGH/MEDIUM/LOW with
explicit reasons so the agent learns from its own overclaims.

Integrated at two hook-points:
  1. record_candidate (in findings.py) — every candidate passes through here.
  2. The system prompt (in prompts.py) — the agent self-filters before it writes.

No finding ever reaches Muhammed without this check. Keep the zero-FP bar.
"""
from __future__ import annotations

import re

# --- critical evidence requirements -----------------------------------------
# A CRITICAL bug must satisfy ALL of these. If any fail, the finding is
# downgraded to HIGH and the agent is told exactly what's missing.

CRITICAL_EVIDENCE_REQUIREMENTS = [
    ("primitive",
     "What is the EXACT exploit primitive? (arbitrary kernel r/w, RCE, token steal, "
     "cloud credential leak). State the primitive explicitly — 'the IOCTL copies "
     "user data to kernel without bounds check' is not a primitive; 'this yields "
     "an arbitrary kernel write' IS."),
    ("attack_vector",
     "What is the attack vector and who can reach it? Unauthenticated remote? "
     "Standard local user? Local admin? AppContainer? Physical access? A bug that "
     "requires local admin to trigger is NOT critical unless it escapes the sandbox."),
    ("deployment_scope",
     "How widely deployed is the vulnerable component? Is this a default Windows "
     "driver shipped on 100M+ machines? A SaaS product with 10,000 tenants? Or a "
     "niche gaming anti-cheat on 5,000 Korean PCs? Scope directly determines bounty tier."),
    ("exploit_chain",
     "Can the primitive be turned into a reliable exploit? Describe the exploitation "
     "technique: how you go from the primitive to SYSTEM/rce/data exfiltration. "
     "'Overwrite token' or 'shell via CreateProcess' are the bar — if you can't "
     "describe the full chain, the finding is not confirmed critical."),
    ("mitigation_bypass",
     "Which mitigations must be bypassed? CFG? CET? kCFG? SMEP/SMAP? WDAC? "
     "AppContainer? If the primitive relies on missing mitigations that are enabled "
     "by default on the target OS, state that clearly and explain the bypass."),
]

# Patterns that suggest an agent is overclaiming severity
_OVERCLAIM_PATTERNS = [
    (re.compile(r"potential(ly)?\s+critical", re.I), "hedging on critical"),
    (re.compile(r"could\s+(be|lead\s+to)\s+(critical|rce|system)", re.I), "speculative impact"),
    (re.compile(r"if\s+(an?\s+)?attacker\s+(could|can|were\s+to)", re.I), "conditional — not proven"),
    (re.compile(r"(likely|probably|might|may)\s+(be|have|lead)", re.I), "uncertain language"),
    (re.compile(r"(requires|needs)\s+(further|more)\s+(analysis|investigation|research)", re.I), "unfinished"),
    (re.compile(r"theoretical(ly)?\b", re.I), "theoretical — not demonstrated"),
]

# Keywords that strengthen a critical claim (must be present AND specific)
_CRITICAL_PRIMITIVES = {
    "kernel": [
        "arbitrary kernel write", "arbitrary kernel read",
        "kernel code execution", "token privilege escalation",
        "direct kernel object manipulation",
    ],
    "remote": [
        "remote code execution", "unauthenticated rce",
        "pre-auth rce", "zero-click rce",
    ],
    "privilege": [
        "system token replacement", "kernel shellcode execution",
        "arbitrary physical memory access",
    ],
    "web": [
        "ssrf to cloud metadata", "unauthenticated admin bypass",
        "full database exfiltration", "server-side template injection to rce",
    ],
}

_IMPACT_KEYWORDS = {
    "critical": [
        "100m+", "default install", "all windows versions",
        "no user interaction", "wormable", "zero-click",
        "cloud metadata", "iam credentials",
    ],
}


def classify_severity(title: str = "", cwe: str = "", hypothesis: str = "",
                      evidence: str = "", target: str = "") -> dict:
    """Classify a finding's severity and check critical-evidence requirements.

    Returns {severity, cvss_estimate, critical_evidence: {passed/missing}, flags, downgrade_reason}
    """
    text = f"{title} {cwe} {hypothesis} {evidence}".lower()
    flags: list[str] = []
    evidence_results: dict[str, dict] = {}

    # Stage 1: detect overclaim patterns
    for pattern, flag in _OVERCLAIM_PATTERNS:
        if pattern.search(title) or pattern.search(hypothesis):
            flags.append(f"overclaim:{flag}")

    # Stage 2: check for genuine critical primitives
    has_primitive = False
    primitive_type = "unknown"
    for category, primitives in _CRITICAL_PRIMITIVES.items():
        for p in primitives:
            if p in text:
                has_primitive = True
                primitive_type = category
                break
        if has_primitive:
            break

    # Stage 3: check impact keywords
    has_impact_keyword = any(kw in text for kw in _IMPACT_KEYWORDS["critical"])

    # Stage 4: evaluate critical evidence requirements
    all_evidence_passed = True
    for req_id, req_desc in CRITICAL_EVIDENCE_REQUIREMENTS:
        # Simple heuristic: check if the requirement topic appears specifically
        passed = _check_requirement(req_id, hypothesis, evidence)
        evidence_results[req_id] = {
            "passed": passed,
            "requirement": req_desc[:80],
        }
        if not passed:
            all_evidence_passed = False

    # Stage 5: determine severity
    if has_primitive and has_impact_keyword and all_evidence_passed and not flags:
        severity = "critical"
        cvss = 9.0
        downgrade = ""
    elif has_primitive and (has_impact_keyword or all_evidence_passed):
        severity = "high"
        cvss = 7.5
        missing = [k for k, v in evidence_results.items() if not v["passed"]]
        downgrade = (
            f"Downgraded from critical to HIGH: "
            f"missing evidence for {', '.join(missing) if missing else 'impact verification'}"
        )
    elif has_primitive:
        severity = "high"
        cvss = 7.0
        downgrade = "Insufficient impact/deployment evidence for critical classification."
    elif flags:
        severity = "medium"
        cvss = 5.0
        downgrade = f"Overclaim patterns detected: {', '.join(flags)}"
    else:
        severity = "medium"
        cvss = 5.0
        downgrade = "No critical primitive identified. Restate the exact exploit primitive."

    return {
        "severity": severity,
        "cvss_estimate": cvss,
        "primitive_type": primitive_type,
        "critical_evidence": evidence_results,
        "all_critical_evidence_passed": all_evidence_passed,
        "flags": flags,
        "downgrade_reason": downgrade,
        "is_critical": severity == "critical",
    }


def _check_requirement(req_id: str, hypothesis: str, evidence: str) -> bool:
    """Simple heuristic: does the text address this requirement specifically?"""
    text = f"{hypothesis} {evidence}".lower()
    lookup = {
        "primitive": ["rce", "arbitrary write", "arbitrary read", "code exec",
                       "privilege escalation", "token steal", "shell", "command execution",
                       "sql injection", "ssrf", "authentication bypass"],
        "attack_vector": ["unauthenticated", "standard user", "low privilege",
                          "remote", "local", "network", "http", "api endpoint",
                          "ioctl", "device\\\\", "named pipe", "service"],
        "deployment_scope": ["default", "all versions", "enterprise", "widely deployed",
                             "shipped on", "pre-installed", "cloud", "saas", "tenant"],
        "exploit_chain": ["then", "next", "after", "overwrite", "inject", "spawn",
                          "createprocess", "elevate", "escalate", "pivot"],
        "mitigation_bypass": ["cfg", "cet", "smep", "smap", "wdac", "appcontainer",
                              "guard", "mitigation", "bypass", "signature"],
    }
    keywords = lookup.get(req_id, [])
    return any(kw in text for kw in keywords)


def format_severity_banner(result: dict) -> str:
    """Human-readable severity verdict for the record_candidate output."""
    if result["is_critical"]:
        return (
            "🔴 CRITICAL — verified classification\n"
            f"  Primitive: {result['primitive_type']}\n"
            f"  CVSS estimate: {result['cvss_estimate']:.1f}\n"
            "  All critical-evidence requirements passed.\n"
            "  ⚠ This finding requires PoC reproduction before reporting."
        )
    banner = f"🟡 {result['severity'].upper()}"
    if result["downgrade_reason"]:
        banner += f" — {result['downgrade_reason']}"
    if result["flags"]:
        banner += f"\n  Flags: {', '.join(result['flags'])}"
    if not result["all_critical_evidence_passed"]:
        missing = [k for k, v in result["critical_evidence"].items() if not v["passed"]]
        banner += f"\n  Missing critical evidence: {', '.join(missing)}"
    return banner


def severity_from_text(title: str, cwe: str, hypothesis: str,
                       evidence: str, target: str = "") -> str:
    """Shortcut: return just the severity string (for tool output)."""
    return classify_severity(title, cwe, hypothesis, evidence, target)["severity"]
