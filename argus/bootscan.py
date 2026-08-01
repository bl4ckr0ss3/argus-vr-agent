"""Boot-chain differential analysis for rootkit / bootkit research.

The detonation loop can't see rootkits/bootkits: a kernel rootkit hides from the
live OS (and can tamper with the very tools ARGUS uses), and a bootkit fires at
BOOT, before the OS exists. So this does DIFFERENTIAL boot-chain forensics
instead — capture a baseline, detonate the sample, REBOOT, then compare.

What it captures (all READ-ONLY; nothing on the boot chain is ever written):
  * MBR   — sector 0 of PhysicalDrive0            (MBR bootkits: TDL4, Rovnix)
  * VBR   — the system volume boot sector
  * ESP   — EFI System Partition .efi files + hashes (UEFI bootkits: ESPecter,
            BlackLotus infect \\EFI\\Microsoft\\Boot\\bootmgfw.efi)
  * Secure Boot state
  * BCD   — boot configuration (bootkits flip testsigning / nointegritychecks)
  * drivers — loaded kernel drivers + start mode (BYOVD / kernel rootkits)

Windows-only, needs Administrator (raw device + ESP mount). Everything degrades
gracefully: an inaccessible source records an error, it never crashes.

Workflow:
    python run.py bootscan --baseline    # before
    #  ... detonate the sample, then REBOOT the VM ...
    python run.py bootscan --compare     # after -> boot-chain findings
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import subprocess
from pathlib import Path

import config

_BASELINE = config.STATE_DIR / "bootscan_baseline.json"


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _is_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _run(cmd: str, timeout: int = 60) -> str:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           timeout=timeout, errors="ignore")
        return (r.stdout or "") + (r.stderr or "")
    except Exception as e:
        return f"ERR: {e}"


def _read_sector(path: str, n: int = 512) -> str:
    try:
        with open(path, "rb") as f:
            return _sha(f.read(n))
    except Exception as e:
        return f"ERR: {e}"


def _free_drive_letter() -> str | None:
    for L in "STUVWXYZ":
        if not os.path.exists(f"{L}:\\"):
            return f"{L}:"
    return None


def _esp_files() -> dict:
    """Mount the EFI System Partition, hash its files, unmount."""
    letter = _free_drive_letter()
    if not letter:
        return {"_error": "no free drive letter to mount ESP"}
    m = _run(f"mountvol {letter} /S")
    if any(w in m.lower() for w in ("error", "denied", "invalid", "not ")):
        return {"_error": (m.strip()[:160] or "mountvol /S failed (need Admin/UEFI)")}
    files: dict = {}
    try:
        root = Path(f"{letter}\\")
        for p in root.rglob("*"):
            if p.is_file():
                try:
                    files[str(p.relative_to(root)).lower()] = _sha(p.read_bytes())
                except Exception:
                    files[str(p.relative_to(root)).lower()] = "ERR"
    finally:
        _run(f"mountvol {letter} /D")
    return files


def _secure_boot() -> str:
    out = _run('powershell -NoProfile -Command "Confirm-SecureBootUEFI"')
    if "True" in out:
        return "on"
    if "False" in out:
        return "off"
    return "unknown"


def _drivers() -> dict:
    """Loaded drivers -> {name: {start, state, path}} via driverquery."""
    out = _run("driverquery /v /fo csv")
    drivers: dict = {}
    try:
        rows = list(csv.reader(io.StringIO(out)))
        if not rows:
            return drivers
        idx = {h.strip().lower(): i for i, h in enumerate(rows[0])}

        def col(row, key):
            i = idx.get(key)
            return row[i].strip() if i is not None and i < len(row) else ""

        for row in rows[1:]:
            if not row or not row[0].strip():
                continue
            drivers[row[0].strip()] = {
                "start": col(row, "start mode"),
                "state": col(row, "state"),
                "path": col(row, "path"),
            }
    except Exception:
        pass
    return drivers


def capture() -> dict:
    """Snapshot the current boot-chain state (read-only)."""
    return {
        "admin": _is_admin(),
        "mbr": _read_sector(r"\\.\PhysicalDrive0"),
        "vbr": _read_sector(r"\\.\C:"),
        "secure_boot": _secure_boot(),
        "esp_files": _esp_files(),
        "bcd": _run("bcdedit /enum all"),
        "bcd_firmware": _run("bcdedit /enum firmware"),
        "drivers": _drivers(),
    }


def _diff(before: dict, after: dict) -> list[dict]:
    """Pure diff of two captures -> ranked findings."""
    out: list[dict] = []

    def add(sev, what, detail):
        out.append({"severity": sev, "what": what, "detail": detail})

    if before.get("mbr") != after.get("mbr") and not str(after.get("mbr")).startswith("ERR"):
        add("CRITICAL", "MBR modified", f"{before.get('mbr','?')[:16]} -> {after.get('mbr','?')[:16]} (classic MBR bootkit)")
    if before.get("vbr") != after.get("vbr") and not str(after.get("vbr")).startswith("ERR"):
        add("CRITICAL", "VBR modified", "volume boot record changed")
    if before.get("secure_boot") != after.get("secure_boot"):
        add("CRITICAL", "Secure Boot state changed", f"{before.get('secure_boot')} -> {after.get('secure_boot')}")

    b_esp, a_esp = before.get("esp_files", {}), after.get("esp_files", {})
    keys_b = {k for k in b_esp if not k.startswith("_")}
    keys_a = {k for k in a_esp if not k.startswith("_")}
    for f in sorted(keys_a - keys_b):
        add("HIGH", "ESP file added", f)
    for f in sorted(keys_b - keys_a):
        add("HIGH", "ESP file removed", f)
    for f in sorted(keys_a & keys_b):
        if b_esp[f] != a_esp[f]:
            add("HIGH", "ESP file modified", f"{f} (UEFI boot binary changed)")

    b_dr, a_dr = before.get("drivers", {}), after.get("drivers", {})
    for name in sorted(set(a_dr) - set(b_dr)):
        d = a_dr[name]
        boot = d.get("start", "").lower() in ("boot", "system")
        add("HIGH" if boot else "MEDIUM", "new driver loaded",
            f"{name} (start={d.get('start') or '?'}, path={d.get('path') or '?'})")

    b_bcd = (before.get("bcd") or "").lower()
    a_bcd = (after.get("bcd") or "").lower()
    for flag in ("testsigning", "nointegritychecks", "disableintegritychecks"):
        if flag in a_bcd and flag not in b_bcd:
            add("HIGH", "BCD integrity weakened", f"{flag} enabled (defeats driver signing)")
    if (before.get("bcd") or "") != (after.get("bcd") or ""):
        add("MEDIUM", "BCD changed", "boot config differs — inspect `bcdedit /enum all`")

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    out.sort(key=lambda x: order.get(x["severity"], 9))
    return out


def baseline() -> dict:
    cap = capture()
    _BASELINE.parent.mkdir(parents=True, exist_ok=True)
    _BASELINE.write_text(json.dumps(cap, indent=2), encoding="utf-8")
    return {"ok": True, "path": str(_BASELINE), "capture": cap}


def compare() -> dict:
    if not _BASELINE.exists():
        return {"error": "no baseline — run: python run.py bootscan --baseline"}
    before = json.loads(_BASELINE.read_text(encoding="utf-8"))
    after = capture()
    return {"ok": True, "findings": _diff(before, after), "after": after}


def summarize(cap: dict) -> str:
    esp_n = len([k for k in cap.get("esp_files", {}) if not k.startswith("_")])
    esp_err = cap.get("esp_files", {}).get("_error")
    bits = [
        f"admin={cap.get('admin')}",
        f"MBR={str(cap.get('mbr'))[:12]}",
        f"VBR={str(cap.get('vbr'))[:12]}",
        f"SecureBoot={cap.get('secure_boot')}",
        f"drivers={len(cap.get('drivers', {}))}",
        f"ESP files={esp_n}" + (f" ({esp_err})" if esp_err else ""),
    ]
    return "  ".join(bits)
