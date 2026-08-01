"""run_recon — execute a single allowlisted command.

Safety model (defence in depth, because the model chooses the command):
  1. The base binary must be on config.RECON_ALLOWLIST (the ACTIVE profile).
  2. The full command line must not contain any blocked substring.
  3. A wall-clock timeout bounds every call.

Two profiles, selected by ARGUS_RECON_PROFILE (see config.py):
  - readonly  (default): inspection tools only + a strict block list — ARGUS
    can look but never change system state. Safe to run on your host.
  - offensive (opt-in): the full researcher toolbox (debuggers, network,
    fuzzers, RE, exploit-dev, shells). Effectively arbitrary host execution and
    NOT sandboxed — run it only inside an isolated VM.

The tool's own description (below) is generated from the active profile, so the
model is always told the truth about what it may run.
"""
from __future__ import annotations

import shlex
import subprocess
from pathlib import PurePath

import config
from .base import Tool, cap


def _base_binary(command: str) -> str:
    try:
        parts = shlex.split(command, posix=False)
    except ValueError:
        parts = command.split()
    if not parts:
        return ""
    first = parts[0].strip('"')
    name = PurePath(first).name.lower()
    for ext in (".exe", ".bat", ".cmd", ".ps1", ".com"):
        if name.endswith(ext):
            name = name[: -len(ext)]
    return name


def _is_allowed(command: str) -> tuple[bool, str]:
    low = command.lower()
    for bad in config.RECON_BLOCK_SUBSTRINGS:
        if bad in low:
            return False, f"blocked substring {bad!r}"
    base = _base_binary(command)
    if base not in config.RECON_ALLOWLIST:
        return False, (
            f"base binary {base!r} is not on the recon allowlist. "
            f"Add it to config.RECON_ALLOWLIST if you need it."
        )
    return True, ""


def make_run_recon() -> Tool:
    def handler(inp: dict) -> str:
        command = (inp.get("command") or "").strip()
        if not command:
            return "ERROR: command is required."
        ok, why = _is_allowed(command)
        if not ok:
            return f"REFUSED: {why}"
        timeout = min(int(inp.get("timeout", 120)), 300)
        try:
            proc = subprocess.run(
                command, shell=True, capture_output=True, text=True,
                timeout=timeout, errors="ignore",
            )
        except subprocess.TimeoutExpired:
            return f"ERROR: command timed out after {timeout}s."
        except OSError as e:
            return f"ERROR launching command: {e}"
        out = proc.stdout or ""
        err = proc.stderr or ""
        body = f"$ {command}\n[exit {proc.returncode}]\n"
        if out:
            body += f"--- stdout ---\n{out}\n"
        if err:
            body += f"--- stderr ---\n{err}\n"
        return cap(body, config.TOOL_OUTPUT_CAP)

    if config.RECON_PROFILE == "offensive":
        desc = (
            "Execute a command whose base binary is on the OFFENSIVE allowlist: Sysinternals, "
            "debuggers (cdb/windbg/kd/x64dbg), network (nmap/curl/netcat/ssh), web fuzzers "
            "(ffuf/sqlmap/nuclei), RE (ghidra_headless/radare2/ida), exploit-dev (msfvenom/nasm/gcc), "
            "hash tools (hashcat/john), interpreters (python/node/php/ruby), and shells (cmd/bash). "
            "This runs on the host with no sandbox — you are inside the operator's analysis VM. "
            "Only disk-format/diskpart are blocked. If a tool isn't listed, add it to config.RECON_OFFENSIVE."
        )
    else:
        desc = (
            "Execute a READ-ONLY reconnaissance / inspection command. Allowlisted to inspection "
            "tools only: sigcheck, accesschk, icacls, dumpbin, strings, capa, floss, yara, driverquery, "
            "read-only Sysinternals (pslist/handle/listdlls/tcpview/autoruns), and read-only "
            "PowerShell/reg QUERIES. Destructive verbs, redirection (>), pipes, and network fetches "
            "(curl/Invoke-WebRequest) are refused. If you need a debugger, fuzzer, exploit-dev, or "
            "network tool, DON'T fake it: state the exact command for Muhammed to run by hand, or ask him to "
            "relaunch with ARGUS_RECON_PROFILE=offensive inside a VM."
        )
    return Tool(
        name="run_recon",
        description=desc,
        input_schema={
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Full command line, e.g. 'nmap -sV target.com' or 'cdb -c \"!process 0 0\" -o target.exe'."},
                "timeout": {"type": "integer", "description": "Seconds before the command is killed (default 120, max 300)."},
            },
            "required": ["command"],
        },
        handler=handler,
    )
