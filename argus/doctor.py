"""Preflight environment check — `python run.py doctor`.

Consolidates every setup gotcha into one readiness report so you know, before you
run anything, whether the VM is correctly configured and which MODE it is in:

  * COLLECTION mode  — internet reachable  -> `fetch` works
  * DETONATION mode  — isolated / sinkholed -> `detonate`/`autohunt` are safe

The two modes are mutually exclusive on purpose (collect online, detonate
isolated, never both). Doctor reports which one the VM is currently in and flags
the dangerous overlaps (live credentials present while about to detonate; a
FakeNet sinkhole answering while you try to fetch).

Pure stdlib; the detection helpers are separated so they can be tested offline.
"""
from __future__ import annotations

import shutil
import socket
import urllib.request

import config
from .tools import dynamic

OK, WARN, FAIL = "ok", "warn", "fail"


def detect_tools() -> dict:
    """Where the external tools resolve (None = not on PATH)."""
    return {
        "procmon": shutil.which("procmon") or shutil.which("Procmon64"),
        "tshark": shutil.which("tshark"),
        "fakenet": shutil.which("fakenet"),
        "yara_cli": shutil.which(config.YARA_BIN) or shutil.which("yara"),
    }


def detect_network(timeout: float = 3.0) -> dict:
    """Is there real outbound internet, and is a FakeNet sinkhole intercepting?"""
    dns_ok, tcp_ok, fakenet = False, False, False
    try:
        socket.getaddrinfo("one.one.one.one", 443)
        dns_ok = True
    except Exception:
        pass
    try:
        s = socket.create_connection(("1.1.1.1", 443), timeout)
        s.close()
        tcp_ok = True
    except Exception:
        pass
    # A FakeNet sinkhole resolves EVERYTHING and answers with its banner, so a
    # bogus host that should never resolve will come back with "FakeNet".
    try:
        with urllib.request.urlopen("http://argus-preflight-nx.invalid/", timeout=timeout) as r:
            if b"FakeNet" in r.read(400):
                fakenet = True
    except Exception:
        pass
    return {"dns": dns_ok, "tcp": tcp_ok, "fakenet": fakenet,
            "reachable": dns_ok and tcp_ok and not fakenet}


def detect_credentials() -> dict:
    """Sensitive keys present in THIS environment (the VM should have none)."""
    return {
        "llm_keys": dynamic._detect_live_keys(),
        "malwarebazaar": bool((config.MALWAREBAZAAR_API_KEY or "").strip()),
        "virustotal": bool((config.VT_API_KEY or "").strip()),
    }


def _c(name: str, status: str, detail: str) -> dict:
    return {"name": name, "status": status, "detail": detail}


def assess() -> dict:
    """Run all detections and produce checks + a readiness verdict."""
    tools = detect_tools()
    net = detect_network()
    creds = detect_credentials()

    from . import yara_engine
    ok_y, how_y = yara_engine.available()
    rules_n = len(yara_engine._rule_files())

    checks = []
    # --- tools ---
    checks.append(_c("procmon", OK if tools["procmon"] else WARN,
                     tools["procmon"] or "not on PATH — detonation loses behavioral telemetry"))
    checks.append(_c("tshark", OK if tools["tshark"] else WARN,
                     tools["tshark"] or "not on PATH — detonation loses network capture"))
    checks.append(_c("yara", OK if ok_y else WARN,
                     f"{how_y}, {rules_n} rule file(s)" if ok_y else how_y))

    # --- credentials (VM must be keyless for detonation) ---
    if creds["llm_keys"]:
        checks.append(_c("credentials", FAIL,
                         f"LLM key(s) present: {', '.join(creds['llm_keys'])} — detonation will BLOCK"))
    else:
        checks.append(_c("credentials", OK, "no LLM credentials (detonation-safe)"))

    # --- network mode ---
    if net["fakenet"]:
        checks.append(_c("network", WARN, "FakeNet sinkhole ACTIVE — detonation-ready, but `fetch` cannot reach the internet"))
        mode = "detonation (FakeNet)"
    elif net["reachable"]:
        checks.append(_c("network", OK, "internet reachable — collection mode; isolate before detonating"))
        mode = "collection (online)"
    elif net["dns"] or net["tcp"]:
        checks.append(_c("network", WARN, "partial connectivity — check DNS/route"))
        mode = "unclear"
    else:
        checks.append(_c("network", OK, "isolated (no internet) — detonation-safe; `fetch` won't work here"))
        mode = "detonation (isolated)"

    # --- optional bits ---
    checks.append(_c("goodware", OK if config.GOODWARE_DIR.exists() else WARN,
                     str(config.GOODWARE_DIR) if config.GOODWARE_DIR.exists()
                     else "no corpus — rule quality gate can't FP-test (set ARGUS_GOODWARE)"))
    checks.append(_c("malwarebazaar key", OK if creds["malwarebazaar"] else WARN,
                     "set" if creds["malwarebazaar"] else "unset — `fetch` needs MALWAREBAZAAR_API_KEY"))

    readiness = {
        "detonation": bool(tools["procmon"]) and not creds["llm_keys"],
        "collection": net["reachable"] and creds["malwarebazaar"],
        "mode": mode,
    }
    return {"checks": checks, "readiness": readiness, "network": net}
