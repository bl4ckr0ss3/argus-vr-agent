"""kernel_research — structured kernel/driver analysis for Windows LPE.

Provides high-signal driver enumeration, IOCTL surface analysis, token privilege
inspection, and kernel object queries via Windows built-ins. Every command runs
through run_recon underneath but structured results make the model more effective
at spotting CVE-worthy bugs: exposed IOCTLs, weak access, missing bounds checks.

Never write raw Windows API calls here — delegate to run_recon for all execution.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

import config
from .base import Tool, cap
from .shell import _is_allowed


def _safe_exec(command: str, timeout: int = 60) -> str:
    ok, why = _is_allowed(command)
    if not ok:
        return f"REFUSED: {why}"
    try:
        proc = subprocess.run(
            command, shell=True, capture_output=True, text=True,
            timeout=min(timeout, 300), errors="ignore",
        )
    except subprocess.TimeoutExpired:
        return f"timed out after {timeout}s"
    except OSError as e:
        return f"ERROR: {e}"
    return (proc.stdout or "") + (proc.stderr or "")


def _enum_drivers() -> str:
    """Enumerate all kernel drivers with path, state, and start type."""
    out = _safe_exec("driverquery /v /fo csv", timeout=60)
    if not out.strip():
        return "driverquery returned no data."
    lines = out.strip().split("\n")
    if len(lines) < 2:
        return out

    result = []
    for line in lines[1:]:  # skip header
        parts = [p.strip('"') for p in line.split(",")]
        if len(parts) >= 5:
            result.append(
                f"  {parts[0]:40s}  state={parts[1]:10s}  type={parts[3]:12s}  path={parts[4] if len(parts)>4 else ''}"
            )
    return "\n".join(result[:80]) if result else out  # top 80 drivers


def _token_privs() -> str:
    """Enumerate the current process token privileges."""
    out = _safe_exec("whoami /priv", timeout=30)
    return out


def _service_dacl(service_name: str) -> str:
    """Query a specific service's configuration and security descriptor."""
    qc = _safe_exec(f'sc qc "{service_name}"', timeout=30)
    sd = _safe_exec(f'sc sdshow "{service_name}"', timeout=30)
    return f"--- sc qc ---\n{qc}\n--- sc sdshow ---\n{sd}"


def _driver_ioctls() -> str:
    """Quick IOCTL surface inventory via driverquery + known patterns."""
    out = _safe_exec("driverquery /v /fo list", timeout=60)
    lines = out.split("\n")
    drivers = []
    cur = {}
    for line in lines:
        line = line.strip()
        if "=" in line:
            k, v = line.split("=", 1)
            cur[k.strip().lower()] = v.strip()
        elif not line and cur:
            drivers.append(dict(cur))
            cur = {}
    if cur:
        drivers.append(cur)

    # Filter for third-party / non-Microsoft drivers
    third_party = []
    for d in drivers:
        name = d.get("module name", "")
        path = d.get("path name", "")
        if not name or not path:
            continue
        low_path = path.lower()
        if ("\\system32\\" in low_path or "\\syswow64\\" in low_path) and (
            "microsoft" in low_path or "\\windows\\" in low_path
        ):
            continue
        state = d.get("state", "?")
        if state.lower() == "running":
            third_party.append(f"  {name:40s}  {state}  {path}")

    if not third_party:
        return "No running third-party drivers found."
    return "Running third-party drivers (potential attack surface):\n" + "\n".join(third_party[:40])


def _open_handles() -> str:
    """List handles held by the current process (for token/process inspection)."""
    # handle.exe from Sysinternals
    out = _safe_exec("handle -accepteula", timeout=60)
    return cap(out, config.TOOL_OUTPUT_CAP // 2)


def make_kernel_research() -> Tool:
    def handler(inp: dict) -> str:
        action = (inp.get("action") or "").strip().lower()
        target = (inp.get("target") or "").strip()

        if action == "enum_drivers":
            return _enum_drivers()
        elif action == "token_privs":
            return _token_privs()
        elif action == "service_dacl":
            if not target:
                return "ERROR: target (service name) is required for service_dacl."
            return _service_dacl(target)
        elif action == "driver_ioctls":
            return _driver_ioctls()
        elif action == "open_handles":
            return _open_handles()
        else:
            return (
                f"ERROR: unknown action {action!r}. Available actions:\n"
                "  enum_drivers   — list all kernel drivers (name, state, path)\n"
                "  token_privs    — show current process token privileges\n"
                "  service_dacl   — inspect a service's DACL and config\n"
                "  driver_ioctls  — list running third-party drivers (IOCTL surface)\n"
                "  open_handles   — show handles held by current process\n"
            )

    return Tool(
        name="kernel_research",
        description=(
            "Structured kernel/driver analysis for Windows LPE research. "
            "Available sub-actions:\n"
            "  • enum_drivers — all kernel drivers (path, state, type)\n"
            "  • token_privs — current token privileges (which can you abuse?)\n"
            "  • service_dacl — sc qc + sdshow for a named service (requires 'target')\n"
            "  • driver_ioctls — running third-party drivers (non-MS + running = IOCTL surface)\n"
            "  • open_handles — process handles via Sysinternals handle.exe\n"
            "Use this FIRST when hunting kernel/servile LPE bugs — it gives you the "
            "attack-surface map before you dive into specific binaries."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["enum_drivers", "token_privs", "service_dacl", "driver_ioctls", "open_handles"],
                    "description": "Which kernel analysis to run.",
                },
                "target": {
                    "type": "string",
                    "description": "Service name (required for service_dacl). Optional otherwise.",
                },
            },
            "required": ["action"],
        },
        handler=handler,
    )
