"""Volatility3 memory-forensics wrapper — cross-view rootkit detection.

A kernel rootkit hides from the live OS (it unlinks its objects) but NOT from raw
memory. This runs Volatility3 over a memory dump and CROSS-VIEWS the OS's linked
lists against pool scanning — anything pool-scanning finds that the linked list
omits was unlinked to hide it (DKOM):

    hidden process = windows.psscan  minus  windows.pslist   -> CRITICAL (DKOM)
    hidden driver  = windows.modscan minus  windows.modules  -> CRITICAL
    injected code  = windows.malfind (RWX private regions)   -> HIGH

Needs Volatility3 (`pip install volatility3`, or `vol` on PATH). Get a dump from
the hypervisor (a suspended VMware VM's .vmem IS its RAM) or WinPmem
(`python run.py memscan --acquire dump.raw`).
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

_PLUGINS = ("windows.pslist", "windows.psscan", "windows.modules",
            "windows.modscan", "windows.malfind")


def _vol_cmd() -> list | None:
    exe = shutil.which("vol") or shutil.which("vol.py") or shutil.which("volatility3")
    if exe:
        return [exe]
    try:
        import volatility3  # noqa: F401
        return [sys.executable, "-m", "volatility3"]
    except Exception:
        return None


def available() -> bool:
    return _vol_cmd() is not None


def _run_plugin(dump: str, plugin: str, timeout: int = 900) -> list | None:
    """Run one Volatility3 plugin with the JSON renderer; parse to a list of rows.
    Returns None if the run failed (so a failed plugin is distinguishable from an
    empty-but-successful one)."""
    base = _vol_cmd()
    if not base:
        return None
    cmd = base + ["-q", "-f", dump, "-r", "json", plugin]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="ignore")
        out = (r.stdout or "").strip()
        if not out:
            return [] if r.returncode == 0 else None
        return json.loads(out)
    except Exception:
        return None


def analyze(pslist, psscan, modules, modscan, malfind) -> list[dict]:
    """Pure cross-view analysis of plugin outputs -> ranked findings."""
    findings: list[dict] = []

    def add(sev, what, detail):
        findings.append({"severity": sev, "what": what, "detail": detail})

    # hidden processes: pool-scanned but not in the active-process linked list
    if pslist is not None and psscan is not None:
        listed = {p.get("PID") for p in pslist}
        for p in psscan:
            pid = p.get("PID")
            if pid is not None and pid not in listed:
                add("CRITICAL", "hidden process (DKOM)",
                    f"PID {pid} {p.get('ImageFileName', '?')} — pool-scanned but unlinked from pslist")

    # hidden drivers: pool-scanned but not in the loaded-module list
    if modules is not None and modscan is not None:
        listed = {(m.get("Name") or "").lower() for m in modules}
        for m in modscan:
            nm = (m.get("Name") or "").lower()
            if nm and nm not in listed:
                add("CRITICAL", "hidden driver",
                    f"{m.get('Name')} @ {m.get('Base', '?')} — pool-scanned but not in module list")

    # injected code
    for m in (malfind or [])[:25]:
        add("HIGH", "injected code (malfind)",
            f"PID {m.get('PID', '?')} {m.get('Process', '?')} prot={m.get('Protection', '?')}")

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    findings.sort(key=lambda x: order.get(x["severity"], 9))
    return findings


def scan(dump: str) -> dict:
    if not available():
        return {"error": "Volatility3 not installed — `pip install volatility3` (or put `vol` on PATH)"}
    if not Path(dump).exists():
        return {"error": f"no such dump: {dump}"}
    rows = {name: _run_plugin(dump, name) for name in _PLUGINS}
    findings = analyze(rows["windows.pslist"], rows["windows.psscan"],
                       rows["windows.modules"], rows["windows.modscan"], rows["windows.malfind"])
    stats = {k.split(".")[-1]: (len(v) if isinstance(v, list) else "ERR") for k, v in rows.items()}
    return {"ok": True, "findings": findings, "stats": stats}


def acquire(out_path: str) -> dict:
    """Best-effort live memory acquisition via WinPmem (must be on PATH)."""
    exe = shutil.which("winpmem") or shutil.which("winpmem.exe") or shutil.which("pmem")
    if not exe:
        return {"error": "winpmem not on PATH — get it from github.com/Velocidex/WinPmem, "
                         "or use a hypervisor .vmem dump instead"}
    try:
        subprocess.run([exe, "-o", out_path], capture_output=True, text=True, timeout=1800)
    except Exception as e:
        return {"error": f"winpmem failed: {e}"}
    p = Path(out_path)
    if p.exists() and p.stat().st_size > 0:
        return {"ok": True, "path": out_path, "size_mb": round(p.stat().st_size / (1024 * 1024), 1)}
    return {"error": "acquisition produced no file"}
