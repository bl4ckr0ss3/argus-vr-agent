"""Dynamic malware analysis — execute a sample in a controlled VM and observe behavior.

⚠ VM ONLY — this tool EXECUTES the sample. Run ONLY inside an isolated Windows VM
(host-only networking, no shared folders, snapshot before detonation). ARGUS
orchestrates the monitoring, executes the sample, and collects behavioral telemetry.

Monitoring probes (set up before execution):
  1. Process Monitor (procmon) — captures process tree, file I/O, registry, thread activity
  2. Network capture (tshark/tshark) — DNS, HTTP, C2 traffic
  3. Registry snapshot (reg) — before/after comparison
  4. File system snapshot (dir /s) — files created/modified/deleted
  5. API Monitor — optional, if api-monitor is installed

Workflow:
  1. Take baseline snapshots (registry, filesystem, process list)
  2. Start procmon + tshark captures in the background
  3. Execute the sample with a timeout
  4. Stop captures, collect logs
  5. Take after-snapshots, diff against baselines
  6. Produce a behavioral report

All outputs saved to runs/malware/<sample_hash>/.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from datetime import datetime
from pathlib import Path

import config
from .base import Tool, cap

_DYNAMIC_DIR = config.RUNS_DIR / "dynamic"
_DYNAMIC_DIR.mkdir(parents=True, exist_ok=True)

# Maximum time (seconds) the sample is allowed to execute before forced kill.
# Tunable via ARGUS_DETONATE_MAX — a gated/beaconing sample often needs longer
# than 120s to get past its env check and fire, so the cap is configurable
# instead of hard-wired. The CLI --timeout is still honoured up to this ceiling.
_MAX_EXECUTION_SECONDS = int(os.environ.get("ARGUS_DETONATE_MAX", "600"))
# Injection loaders (GuLoader, packed droppers) run a launcher that spawns/hollows
# a child and EXITS in a second or two — the malicious behaviour is in the child.
# If we stop monitoring the instant the launcher dies we capture nothing. So after
# the launcher exits, keep the probes running for a short settle window (capped by
# the overall timeout) to catch the injected payload's file/net/process activity.
_SETTLE_SECONDS = int(os.environ.get("ARGUS_SETTLE_SECONDS", "20"))

# --- Credential guard ------------------------------------------------------
# A detonated binary runs with our privileges and can read the process
# environment and any .env in the repo, then exfiltrate it. So the machine that
# EXECUTES a sample must hold NO API credentials. These are every provider secret
# ARGUS knows how to read (see config.resolve_llm); if any is live in the
# environment when a detonation is requested, we refuse.
_SECRET_ENV_VARS = (
    "ARGUS_API_KEY", "DEEPSEEK_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
    "MOONSHOT_API_KEY", "KIMI_API_KEY", "GLM_API_KEY", "ZHIPU_API_KEY",
    "OPENROUTER_API_KEY", "AGENTROUTER_API_KEY", "TOKENROUTER_API_KEY",
)
# Obvious non-secrets to ignore so a placeholder in .env doesn't trip the guard.
_PLACEHOLDER_PREFIXES = ("your", "sk-...", "sk-or-...", "changeme", "<", "xxx", "...")


def _detect_live_keys() -> list[str]:
    """Names of env vars that currently hold a real-looking (non-placeholder) secret."""
    found = []
    for name in _SECRET_ENV_VARS:
        val = os.environ.get(name, "").strip()
        if len(val) >= 12 and not val.lower().startswith(_PLACEHOLDER_PREFIXES):
            found.append(name)
    return found


def _safe_exec(command: str, timeout: int = 60, capture: bool = True) -> str:
    """Execute a command and return output. Handles errors gracefully."""
    try:
        proc = subprocess.run(
            command, shell=True, capture_output=capture, text=True,
            timeout=timeout, errors="ignore",
        )
        return (proc.stdout or "") + "\n" + (proc.stderr or "")
    except subprocess.TimeoutExpired:
        return f"[timed out after {timeout}s]"
    except OSError as e:
        return f"[ERROR: {e}]"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def _registry_snapshot(label: str, out_dir: Path) -> Path:
    """Export persistence-relevant registry state for a before/after diff.

    Autostart keys are small, so we recurse them (/s). The Services hive is
    enumerated NAMES-ONLY (no /s): a recursive dump is ~10k+ lines of stock
    perf-counter/linkage subkeys that truncate under a timeout and fabricate
    thousands of bogus "new" keys. A new *service* shows up as a new top-level
    key name — which a names-only listing captures cleanly and stably."""
    path = out_dir / f"registry_{label}.txt"
    autostart = [
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    ]
    lines = [f"=== Registry snapshot: {label} ==="]
    for hive in autostart:
        out = _safe_exec(f'reg query "{hive}" /s 2>&1', timeout=30)
        lines.append(f"\n--- {hive} ---\n{out}")
    # Services: names only (NO /s) — stable, fast, and a new key == new service.
    svc = _safe_exec(r'reg query "HKLM\System\CurrentControlSet\Services" 2>&1', timeout=60)
    lines.append("\n--- HKLM\\System\\CurrentControlSet\\Services (names) ---\n" + svc)
    path.write_text("\n".join(lines), encoding="utf-8", errors="ignore")
    return path


def _filesystem_snapshot(label: str, out_dir: Path, target_dirs: list[str]) -> Path:
    """Take a file listing of key directories for before/after diff."""
    path = out_dir / f"files_{label}.txt"
    lines = [f"=== Filesystem snapshot: {label} ==="]
    for d in target_dirs:
        out = _safe_exec(f'dir /s /b "{d}" 2>&1', timeout=60)
        lines.append(f"\n--- {d} ---\n{out}")
    path.write_text("\n".join(lines), encoding="utf-8", errors="ignore")
    return path


def _local_capture_dir() -> Path:
    d = Path(tempfile.gettempdir()) / "argus_capture"
    d.mkdir(parents=True, exist_ok=True)
    return d


# Common Sysinternals install locations — checked when procmon is not on PATH
# (an elevated shell often has a different PATH than the one vm-setup.ps1 patched).
_PROCMON_DIRS = (
    r"C:\Tools\Sysinternals", r"C:\Sysinternals", r"C:\Tools",
    r"C:\Program Files\Sysinternals", r"C:\ProgramData\chocolatey\bin",
)
_PROCMON_NAMES = ("Procmon64.exe", "Procmon.exe", "procmon.exe")


def _procmon_exe() -> str | None:
    """Resolve the Process Monitor executable by full path. Bare `procmon` fails
    the instant it isn't on PATH, so we look, in order: an explicit override
    (ARGUS_PROCMON), the PATH, then the usual Sysinternals install dirs."""
    override = os.environ.get("ARGUS_PROCMON", "").strip().strip('"')
    if override and Path(override).exists():
        return override
    for name in ("procmon", "Procmon64", "Procmon"):
        hit = shutil.which(name)
        if hit:
            return hit
    for d in _PROCMON_DIRS:
        for name in _PROCMON_NAMES:
            cand = Path(d) / name
            if cand.exists():
                return str(cand)
    return None


def _start_procmon_capture(out_dir: Path) -> dict:
    """Start Process Monitor capture. The backing file is written to LOCAL disk —
    procmon corrupts a .pml if it captures directly to a network/shared folder
    (ARGUS_RUNS on a VMware share). The finished file is copied to out_dir on stop."""
    local_pml = _local_capture_dir() / "procmon.pml"
    try:
        local_pml.unlink(missing_ok=True)  # drop any stale capture
    except OSError:
        pass
    exe = _procmon_exe()
    if not exe:
        # Surface it loudly instead of silently producing an INCONCLUSIVE verdict.
        return {"pid": None, "log_local": str(local_pml),
                "log": str(out_dir / "procmon.pml"), "command": None,
                "error": "procmon not found — add Sysinternals to PATH or set "
                         "ARGUS_PROCMON to the full Procmon.exe path"}
    cmd = f'"{exe}" /BackingFile "{local_pml}" /Quiet /AcceptEula /Minimized'
    proc = subprocess.Popen(cmd, shell=True)
    time.sleep(3)  # give procmon time to start
    return {"pid": proc.pid, "log_local": str(local_pml), "exe": exe,
            "log": str(out_dir / "procmon.pml"), "command": cmd}


def _stop_procmon_capture(handle: dict | None = None) -> str:
    """Stop Process Monitor and copy the (now-closed) local .pml into out_dir.
    A one-time copy to a share is safe; only live capture to a share corrupts."""
    _safe_exec("procmon /Terminate", timeout=10)
    time.sleep(2)
    if handle and handle.get("log_local") and handle.get("log"):
        try:
            src = Path(handle["log_local"])
            if src.exists() and src.stat().st_size > 0:
                shutil.copy2(src, handle["log"])
        except Exception:
            pass
    return "procmon terminated"


# Pseudo / non-NIC capture sources that `tshark -D` lists but which never carry
# a sample's traffic — skip them when auto-selecting an interface.
_IFACE_SKIP = (
    "loopback", "usbpcap", "ciscodump", "etwdump", "randpkt",
    "sshdump", "udpdump", "wifidump", "dpauxmon", "sdjournal",
)


def _pick_capture_iface() -> str:
    """Choose which interface tshark captures on.

    The old code blindly used `-i 1`, which on a multi-NIC VM usually lands on a
    virtual/WFP pseudo-adapter that carries no traffic — you get an empty pcap
    even when the sample beacons. Resolution order:
      1. ARGUS_CAPTURE_IFACE  (an index like "4" or a name like "Ethernet0")
      2. first real Ethernet-like NIC from `tshark -D`
      3. first non-pseudo NIC
      4. "1" (last-resort fallback = old behaviour)
    """
    override = os.environ.get("ARGUS_CAPTURE_IFACE", "").strip()
    if override:
        return override
    try:
        out = subprocess.run("tshark -D", shell=True, capture_output=True,
                             text=True, timeout=20).stdout
    except Exception:
        return "1"
    real = []  # [(index, friendly_name_lower)]
    for line in out.splitlines():
        m = re.match(r"\s*(\d+)\.\s+(\S+)(?:\s+\((.*)\))?", line)
        if not m:
            continue
        idx, dev, name = m.group(1), m.group(2), (m.group(3) or "")
        blob = f"{dev} {name}".lower()
        if any(s in blob for s in _IFACE_SKIP):
            continue
        real.append((idx, name.lower()))
    for idx, name in real:            # prefer a genuine Ethernet adapter
        if "ethernet" in name:
            return idx
    return real[0][0] if real else "1"


def _start_network_capture(out_dir: Path, iface: str = "1") -> subprocess.Popen | None:
    """Start tshark capture on `iface`. Returns the process or None if unavailable."""
    pcap = out_dir / "network.pcap"
    cmds = [
        f'tshark -i {iface} -w "{pcap}" -q',
        f'tshark -w "{pcap}" -q',   # fallback: let tshark pick its own default
    ]
    for cmd in cmds:
        try:
            proc = subprocess.Popen(cmd, shell=True)
            time.sleep(2)
            return proc
        except Exception:
            continue
    return None


def _stop_network_capture(proc: subprocess.Popen | None) -> str:
    if proc is None:
        return "no network capture active"
    proc.terminate()
    time.sleep(2)
    return "network capture stopped"


def _start_fakenet() -> subprocess.Popen | None:
    """Best-effort launch of FakeNet-NG so a C2-gated payload actually fires.

    Opt-in via ARGUS_FAKENET: set it to "1" (use `fakenet` on PATH) or to the
    full path of the FakeNet-NG executable. FakeNet answers DNS/HTTP for the C2
    (e.g. api2.checkenv.cloud) so the sample passes its env check. Untested on
    non-VM hosts and non-fatal — if it can't start, detonation still proceeds
    (you'd just capture a dormant sample). Needs Admin + FakeNet's own config."""
    val = os.environ.get("ARGUS_FAKENET", "").strip()
    if not val:
        return None
    exe = "fakenet" if val in ("1", "true", "yes") else val
    # Resolve the binary FIRST. With shell=True a missing command does NOT raise —
    # cmd.exe just prints "not recognized" and exits, and Popen still returns a
    # (dead) process, which would be misreported as "FakeNet active". Verify it
    # exists, launch WITHOUT a shell, then confirm it stayed up.
    resolved = shutil.which(exe) or (exe if os.path.exists(exe) else None)
    if not resolved:
        return None
    # FakeNet-NG loads its default config (configs/default.ini) relative to its
    # OWN directory, so it exits instantly if launched from autohunt's cwd. Run
    # it from the exe's folder, and pass the bundled default config explicitly
    # when we can find one, so a full-path ARGUS_FAKENET just works.
    exe_dir = os.path.dirname(resolved) or None
    cmd = [resolved]
    for cfg in ("configs/default.ini", "default.ini"):
        cfg_path = os.path.join(exe_dir, cfg) if exe_dir else cfg
        if exe_dir and os.path.exists(cfg_path):
            cmd = [resolved, "-c", cfg_path]
            break
    try:
        proc = subprocess.Popen(cmd, cwd=exe_dir,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError:
        return None
    time.sleep(4)  # let it bind interfaces before the sample runs
    if proc.poll() is not None:  # already exited -> failed to start/bind
        return None
    return proc


def _stop_fakenet(proc: subprocess.Popen | None) -> str:
    if proc is None:
        return "fakenet not started"
    try:
        proc.terminate()
        time.sleep(2)
    except OSError:
        pass
    return "fakenet stopped"


def _execute_sample(sample_path: str, timeout: int = _MAX_EXECUTION_SECONDS) -> dict:
    """Execute the sample and return exit info. NEVER call strip/clean — this IS execution."""
    try:
        proc = subprocess.Popen(
            sample_path, shell=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        start = time.time()
        settled = 0.0
        try:
            proc.wait(timeout=timeout)
            exit_code = proc.returncode
            killed = False
            # Launcher exited — keep the probes capturing for a settle window so an
            # injected child (the real payload) is observed. Never exceed the timeout.
            elapsed = time.time() - start
            settle = max(0.0, min(_SETTLE_SECONDS, timeout - elapsed))
            if settle:
                time.sleep(settle)
                settled = settle
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            exit_code = -1
            killed = True

        return {
            "executed": True,
            "exit_code": exit_code,
            "killed_after_timeout": killed,
            "runtime_seconds": timeout if killed else round(time.time() - start, 1),
            "settle_seconds": round(settled, 1),
        }
    except OSError as e:
        return {"executed": False, "error": str(e)}


def _process_tree_snapshot() -> str:
    """Capture current process tree."""
    return _safe_exec(
        'tasklist /v /fo csv 2>&1',
        timeout=30,
    )


def _collect_sample_info(sample_path: str, out_dir: Path) -> dict:
    """Run static analysis on the sample before detonation for identification."""
    from .malware import analyze_file
    static = analyze_file(Path(sample_path))
    info_path = out_dir / "sample_info.json"
    info_path.write_text(json.dumps(static, indent=2), encoding="utf-8")
    return static


# ---------------------------------------------------------------------------
# automatic post-detonation analysis — so ONE `detonate` yields the verdict
# instead of the operator hand-running Compare-Object / Import-Csv afterward.
# ---------------------------------------------------------------------------
# Observer noise to strip from diffs: our own procmon driver + snapshot headers +
# artifacts we ourselves wrote into the run dir.
_DIFF_NOISE = ("procmon24", "process monitor", "=== registry snapshot",
               "=== filesystem snapshot", "network.pcap", "procmon.pml",
               "procmon.csv", "runs\\dynamic", "runs/dynamic")
# Directories whose appearance in a diff signals staging/persistence.
_STAGING_HINTS = ("appdata", "\\temp\\", "programdata", "\\startup\\",
                  "\\start menu\\", "roaming")
# Extensions that make a staged file a real payload rather than benign scratch.
# A lone GUID-named .tmp / .log / cache file in Temp is normal app behaviour;
# an .exe/.dll/.ps1 dropped into a staging dir is the actual "drop" signal.
_PAYLOAD_EXTS = (".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".psm1",
                 ".vbs", ".vbe", ".js", ".jse", ".hta", ".jar", ".com",
                 ".pif", ".msi", ".sys", ".cpl", ".wsf")


def _is_payload_path(f: str) -> bool:
    fl = f.lower().rstrip()
    return any(fl.endswith(ext) for ext in _PAYLOAD_EXTS)


# Service subkeys that are OS bookkeeping, never a persistence signal. A real
# service-based persistence is a NEW top-level service with an ImagePath — not a
# perf-counter / linkage / enum leaf under an existing service.
_SERVICE_NOISE = ("linkage", "\\performance", ".net clr", "\\enum", "\\security",
                  "\\parameters", "\\instances", "\\aux", "\\type library")
# Above this many "new" registry lines, the baseline snapshot is untrustworthy
# (a truncated/racing `reg query /s` over the Services hive), so we do NOT treat
# the giant Services diff as real change — only the small, stable Run keys.
_REG_DIFF_SANITY = 150


def _persistence_hits(reg_new: list[str]) -> list[str]:
    """Filter a registry diff down to genuine persistence keys (Run + new services)."""
    hits = []
    for r in reg_new:
        rl = r.lower().lstrip()
        if not rl.startswith(("hkey_", "hklm", "hkcu", "hku")):
            continue  # value/indented lines aren't keys
        if "currentversion\\run" in rl:
            hits.append(r)
        elif "\\services\\" in rl and not any(n in rl for n in _SERVICE_NOISE):
            hits.append(r)
    return hits


# MITRE ATT&CK techniques each behavioral signal maps to — so a verdict is
# self-explaining and a writeup is publishable with standard references.
_ATTACK = {
    "persistence":     ("T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys"),
    "service":         ("T1543.003", "Create or Modify System Process: Windows Service"),
    "network":         ("T1071",     "Application Layer Protocol (C2)"),
    "executable-drop": ("T1105",     "Ingress Tool Transfer / staged payload"),
    "child-processes": ("T1059",     "Command and Scripting Interpreter"),
    "packed":          ("T1027.002", "Obfuscated Files or Information: Software Packing"),
}
# Weight each signal contributes to a suspicious-verdict confidence score.
# A YARA hit is a curated-signature match (strong, static, independent of the
# dynamic run), so it carries the most weight.
_SIGNAL_WEIGHT = {"yara-match": 40, "persistence": 30, "executable-drop": 30,
                  "network": 20, "packed": 20, "child-processes": 15}


def _attack_tags(signals: list[str], persistence: list[str]) -> list[dict]:
    """Map behavioral signals to ATT&CK techniques (deduped, stable order)."""
    tags: list[dict] = []
    seen = set()

    def add(key):
        tech = _ATTACK.get(key)
        if tech and tech[0] not in seen:
            seen.add(tech[0])
            tags.append({"id": tech[0], "name": tech[1], "signal": key})

    for s in signals:
        add(s)
    # A service-key persistence is a distinct technique from a Run-key one.
    if any("\\services\\" in p.lower() for p in persistence):
        add("service")
    return tags


def _confidence(verdict: str, signals: list[str], procmon_parsed: bool,
                reg_unreliable: bool) -> int:
    """A 0-100 confidence in the verdict. Corroboration (more/stronger signals,
    a reliable baseline, a parsed procmon) raises it; missing telemetry lowers it."""
    if verdict == "suspicious":
        score = sum(_SIGNAL_WEIGHT.get(s, 10) for s in signals)
        conf = min(95, 45 + score)
        if reg_unreliable and signals == ["persistence"]:
            conf = min(conf, 60)  # only signal came from a shaky registry diff
        return conf
    if verdict == "benign":
        conf = 85
        if reg_unreliable:
            conf -= 15  # couldn't fully trust the registry baseline
        return conf
    return 30  # inconclusive: telemetry was incomplete


def _confidence_label(conf: int) -> str:
    return "high" if conf >= 80 else ("medium" if conf >= 55 else "low")


def _diff_new_lines(before: Path, after: Path, extra_noise: tuple = ()) -> list[str]:
    """Non-empty lines in `after` absent from `before`, minus known noise."""
    try:
        b = set(before.read_text(encoding="utf-8", errors="ignore").splitlines())
        a = after.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []
    noise = _DIFF_NOISE + tuple(n.lower() for n in extra_noise)
    out = []
    for line in a:
        s = line.strip()
        if not s or line in b:
            continue
        if any(n in s.lower() for n in noise):
            continue
        out.append(s)
    return out


def _procmon_to_csv(out_dir: Path) -> Path | None:
    """Convert the procmon .pml to CSV headlessly. Returns the CSV path or None."""
    pml = out_dir / "procmon.pml"
    # Prefer the local capture copy — faster, and avoids reading a big .pml back
    # from a network share (out_dir may be ARGUS_RUNS on a VMware shared folder).
    local_pml = _local_capture_dir() / "procmon.pml"
    if local_pml.exists() and local_pml.stat().st_size > 0:
        pml = local_pml
    if not pml.exists() or pml.stat().st_size == 0:
        return None
    csv_path = out_dir / "procmon.csv"
    if csv_path.exists() and csv_path.stat().st_size > 0:
        return csv_path  # already converted (e.g. a reanalyze pass) — reuse it
    # Resolve the actual binary and invoke it by full path — bare "procmon" can
    # fail here even when the capture worked (fresh shell / PATHEXT quirks).
    exe = _procmon_exe()
    if not exe:
        return None
    # A big .pml takes a while; scale the timeout with size (128 MB was timing
    # out at the old fixed 180s and leaving the verdict INCONCLUSIVE).
    mb = pml.stat().st_size / (1024 * 1024)
    timeout = max(300, int(mb) * 4)
    _safe_exec(f'"{exe}" /OpenLog "{pml}" /SaveAs "{csv_path}"', timeout=timeout)
    return csv_path if (csv_path.exists() and csv_path.stat().st_size > 0) else None


def _procmon_summary(out_dir: Path, sample_name: str) -> dict:
    """Parse the procmon CSV into a behavioral summary for the sample process."""
    import csv as _csv
    summary = {"csv": None, "ops": {}, "net": [], "writes": [], "spawned": []}
    csv_path = _procmon_to_csv(out_dir)
    if not csv_path:
        return summary
    summary["csv"] = str(csv_path)
    needle = sample_name.lower()
    net, writes, spawned = set(), set(), set()
    try:
        with open(csv_path, newline="", encoding="utf-8", errors="ignore") as f:
            for row in _csv.DictReader(f):
                pname = (row.get("Process Name") or "").lower()
                op = (row.get("Operation") or "").strip()
                path = (row.get("Path") or "").strip()
                # Process Create rows are logged under the PARENT, so always
                # capture spawns whose parent OR child is our sample.
                if op == "Process Create" and (needle in pname or needle in path.lower()):
                    spawned.add(path or (row.get("Detail") or ""))
                    continue
                if needle not in pname:
                    continue
                summary["ops"][op] = summary["ops"].get(op, 0) + 1
                if op.startswith(("TCP", "UDP")):
                    net.add(path)
                elif "Write" in op and path:
                    writes.add(path)
    except OSError:
        return summary
    summary["net"] = sorted(net)[:60]
    summary["writes"] = sorted(writes)[:60]
    summary["spawned"] = sorted(x for x in spawned if x)[:60]
    return summary


def analyze_detonation(out_dir: Path, static: dict, exec_result: dict) -> dict:
    """Structured heuristic analysis of a completed detonation.

    Returns a dict the loop / panel / publish pipeline can read programmatically:
      verdict: "suspicious" | "benign" | "inconclusive"
      signals, persistence, net, staged, staged_payloads, spawned, packed, ...
    This is triage signal, not proof — hence a plain-language verdict, never an
    authoritative malware label.
    """
    sample_name = static.get("name", "") or ""
    reg_new = _diff_new_lines(out_dir / "registry_before.txt", out_dir / "registry_after.txt")
    fs_new = _diff_new_lines(out_dir / "files_before.txt", out_dir / "files_after.txt",
                             extra_noise=(str(out_dir),))
    pm = _procmon_summary(out_dir, sample_name)

    # A truncated/racing baseline over the huge Services hive can fabricate
    # thousands of bogus "new" keys. If the raw diff is implausibly large, treat
    # the baseline as unreliable and trust only the small, stable Run keys.
    reg_unreliable = len(reg_new) > _REG_DIFF_SANITY
    persistence = _persistence_hits(reg_new)
    if reg_unreliable:
        persistence = [p for p in persistence if "currentversion\\run" in p.lower()]
    staged = [f for f in (fs_new + pm["writes"]) if any(h in f.lower() for h in _STAGING_HINTS)]
    staged_payloads = [f for f in staged if _is_payload_path(f)]
    entropy = static.get("entropy") or (static.get("pe", {}) or {}).get("entropy") or 0
    packed = isinstance(entropy, (int, float)) and entropy >= 7.2
    procmon_parsed = pm["csv"] is not None
    yara_hits = [str(r) for r in (static.get("yara") or [])]
    try:
        from .. import packer as _packer
        packer_info = _packer.identify(static)
    except Exception:
        packer_info = {"packer": None, "confidence": None, "indicators": []}

    signals = []
    if yara_hits:
        signals.append("yara-match")
    if persistence:
        signals.append("persistence")
    if pm["net"]:
        signals.append("network")
    if staged_payloads:
        signals.append("executable-drop")
    if pm["spawned"]:
        signals.append("child-processes")
    if packed:
        signals.append("packed")

    if signals:
        verdict = "suspicious"
        verdict_text = "SUSPICIOUS — indicators: " + ", ".join(signals)
    elif not procmon_parsed:
        verdict = "inconclusive"
        verdict_text = ("INCONCLUSIVE — no persistence/drops seen, but procmon wasn't "
                        "parsed (endpoints unknown)")
    else:
        verdict = "benign"
        verdict_text = ("No malicious behavior observed — no persistence, no network, "
                        "no drops, not packed")

    confidence = _confidence(verdict, signals, procmon_parsed, reg_unreliable)
    attack = _attack_tags(signals, persistence)

    return {
        "verdict": verdict, "verdict_text": verdict_text, "signals": signals,
        "confidence": confidence, "confidence_label": _confidence_label(confidence),
        "attack": attack,
        "persistence": persistence, "net": pm["net"], "staged": staged,
        "staged_payloads": staged_payloads, "spawned": pm["spawned"],
        "packed": packed, "entropy": entropy, "procmon_parsed": procmon_parsed,
        "packer": packer_info, "yara": yara_hits,
        "reg_unreliable": reg_unreliable, "reg_raw_diff": len(reg_new),
        "sample": sample_name, "sha256": static.get("hashes", {}).get("sha256", ""),
    }


def write_intel_bundle(out_dir: Path, struct: dict, static: dict | None = None) -> dict | None:
    """Auto-generate the shareable detection bundle for a run: iocs.json, iocs.csv
    (defanged), and sigma.yml. Returns {ioc_count, sigma_count} or None on failure."""
    try:
        from .. import ioc as _ioc, sigma_gen as _sigma
        iocs = _ioc.extract_from(struct, static)
        (out_dir / "iocs.json").write_text(json.dumps(iocs, indent=2), encoding="utf-8")
        (out_dir / "iocs.csv").write_text(_ioc.to_csv(iocs, do_defang=True), encoding="utf-8")
        sig = _sigma.generate(struct)
        if sig["count"]:
            (out_dir / "sigma.yml").write_text(sig["text"], encoding="utf-8")
        return {"ioc_count": sum(len(v) for v in iocs.values()), "sigma_count": sig["count"]}
    except Exception:
        return None


def _format_findings(s: dict) -> list[str]:
    """Render analyze_detonation() output as the human-facing KEY FINDINGS block."""
    lines = ["", "===== KEY FINDINGS (auto) ====="]
    lines.append(f"Persistence (Run/Services): {len(s['persistence'])}")
    for r in s["persistence"][:8]:
        lines.append(f"  ! {r}")
    if s.get("reg_unreliable"):
        lines.append(f"  (registry baseline unstable: {s.get('reg_raw_diff','?')} raw diffs — "
                     "Services hive diff discarded as snapshot noise; only Run keys counted)")
    lines.append(f"Network endpoints (procmon): {len(s['net'])}")
    for n in s["net"][:12]:
        lines.append(f"  -> {n}")
    if not s["procmon_parsed"]:
        lines.append("  (procmon CSV unavailable — is `procmon` on PATH? network intent not parsed)")
    lines.append(f"Child processes spawned: {len(s['spawned'])}")
    for sp in s["spawned"][:8]:
        lines.append(f"  + {sp}")
    lines.append(f"Files written to AppData/Temp/ProgramData: {len(s['staged'])}"
                 f"  (executable drops: {len(s['staged_payloads'])})")
    for f in s["staged"][:8]:
        lines.append(f"  {'!! ' if _is_payload_path(f) else '~  '}{f}")
    if s["staged"] and not s["staged_payloads"]:
        lines.append("  (all non-executable — normal temp/cache scratch, not a payload drop)")
    pk = s.get("packer") or {}
    if pk.get("packer"):
        lines.append(f"Packed/encrypted (entropy {s['entropy']}): YES — packer: "
                     f"{pk['packer']} ({pk.get('confidence')})")
        for ind in pk.get("indicators", [])[:4]:
            lines.append(f"    · {ind}")
    else:
        lines.append(f"Packed/encrypted (entropy {s['entropy']}): {'YES' if s['packed'] else 'no'}")
    if s.get("yara"):
        lines.append(f"YARA matches ({len(s['yara'])}): " + ", ".join(s["yara"][:8]))
    if s.get("attack"):
        lines.append("ATT&CK: " + ", ".join(f"{t['id']} ({t['signal']})" for t in s["attack"]))
    if s.get("vt"):
        vt = s["vt"]
        lines.append(f"VirusTotal: {vt.get('summary', 'n/a')}")
    conf = s.get("confidence")
    conf_str = f"  [confidence {conf}% · {s.get('confidence_label','?')}]" if conf is not None else ""
    lines.append(f"VERDICT (heuristic): {s['verdict_text']}{conf_str}")
    return lines


def _generate_behavioral_report(sample_hash: str, out_dir: Path,
                                static: dict, exec_result: dict,
                                findings: list[str] | None = None) -> str:
    """Produce the final behavioral analysis report."""
    lines = [
        f"# Dynamic Analysis Report",
        f"Sample: {static.get('name', '?')}",
        f"SHA256: {sample_hash}",
        f"Analysis time: {datetime.now().isoformat()}",
    ]
    # Lead with the auto-computed verdict so the report answers the question up
    # front instead of just pointing at raw artifacts.
    if findings:
        lines.append("\n## Key Findings")
        lines.extend(findings)

    lines += [
        f"",
        f"## Execution",
        f"- Executed: {exec_result.get('executed')}",
        f"- Exit code: {exec_result.get('exit_code', '?')}",
    ]
    if exec_result.get("killed_after_timeout"):
        lines.append(f"- ⚠ KILLED after {exec_result.get('runtime_seconds', '?')}s timeout")

    lines.append(f"\n## Static Identification\n{json.dumps(static, indent=2)[:1000]}")

    # Procmon log
    pml = out_dir / "procmon.pml"
    if pml.exists():
        size_mb = pml.stat().st_size / (1024 * 1024)
        lines.append(f"\n## Process Monitor\n- Log: {pml} ({size_mb:.1f} MB)")
        lines.append("- Open in Procmon GUI for full interactive analysis")
        # Try quick CSV summary
        csv = out_dir / "procmon_summary.csv"
        if csv.exists():
            lines.append(f"- Summary CSV: {csv}")

    # Network capture
    pcap = out_dir / "network.pcap"
    if pcap.exists():
        size_kb = pcap.stat().st_size / 1024
        lines.append(f"\n## Network Capture\n- PCAP: {pcap} ({size_kb:.0f} KB)")
        lines.append("- Open in Wireshark for full analysis")
        # Try tshark summary
        conv = _safe_exec(f'tshark -r "{pcap}" -z conv,tcp -q 2>&1', timeout=30)
        if conv.strip():
            lines.append(f"\n```\n{conv[:1500]}\n```")

    # Registry diff
    reg_before = out_dir / "registry_before.txt"
    reg_after = out_dir / "registry_after.txt"
    if reg_before.exists() and reg_after.exists():
        lines.append(f"\n## Registry Changes")
        lines.append(f"- Before: {reg_before}")
        lines.append(f"- After: {reg_after}")
        lines.append("- Diff manually with: `fc /L before.txt after.txt`")

    # Filesystem diff
    fs_before = out_dir / "files_before.txt"
    fs_after = out_dir / "files_after.txt"
    if fs_before.exists() and fs_after.exists():
        lines.append(f"\n## Filesystem Changes")
        lines.append(f"- Before: {fs_before}")
        lines.append(f"- After: {fs_after}")

    lines.append(f"\n## Artifacts\n- All artifacts saved to: {out_dir}")

    report_path = out_dir / "report.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    return str(report_path)


# ---------------------------------------------------------------------------
# detonation core (streams stage progress via on_progress)
# ---------------------------------------------------------------------------
def _snapshot_dirs() -> list[str]:
    return [
        os.environ.get("TEMP", r"C:\Windows\Temp"),
        os.environ.get("APPDATA", r"C:\Users\Public\AppData\Roaming"),
        r"C:\ProgramData",
        r"C:\Windows\Tasks",
    ]


def run_snapshot(on_progress=None) -> str:
    """Baseline snapshots only (no execution). Streams progress via on_progress."""
    def emit(line: str) -> None:
        if on_progress:
            try:
                on_progress(line)
            except Exception:
                pass

    out_dir = _DYNAMIC_DIR / f"snapshot_{_timestamp()}"
    out_dir.mkdir(parents=True, exist_ok=True)
    emit(f"Baseline snapshot -> {out_dir}")
    emit("  registry...")
    _registry_snapshot("baseline", out_dir)
    emit("  filesystem...")
    _filesystem_snapshot("baseline", out_dir, _snapshot_dirs()[:3])
    emit("  processes...")
    procs = _process_tree_snapshot()
    (out_dir / "processes_baseline.txt").write_text(procs, encoding="utf-8")
    return f"Snapshots saved to {out_dir}"


def run_detonation(sample, timeout: int = _MAX_EXECUTION_SECONDS, on_progress=None,
                   result: dict | None = None) -> str:
    """Full behavioral detonation.

    Calls on_progress(line) as each stage COMPLETES so a CLI caller can follow
    the run live (the workflow is otherwise silent for minutes during the
    snapshot + execution phases), and also returns the full (capped) report
    text for an LLM tool caller.

    If `result` is a dict it is populated with the structured outcome
    (out_dir, sha256, verdict, signals, net, staged_payloads, ...) so an
    orchestrator (the autonomous hunt loop) can act on the verdict without
    re-parsing text. On a guard block it sets result["blocked"]=True."""
    lines: list[str] = []

    def emit(line: str) -> None:
        lines.append(line)
        if on_progress:
            try:
                on_progress(line)
            except Exception:
                pass

    # SAFETY GUARD (first, before we touch the sample): never execute a live
    # sample while credentials are reachable — a detonated binary can steal them.
    live_keys = _detect_live_keys()
    allow = os.environ.get("ARGUS_DETONATE_ALLOW_KEYS", "").strip().lower() in ("1", "true", "yes")
    if live_keys and not allow:
        emit("⛔ DETONATION BLOCKED — live API credential(s) present in this environment:")
        for k in live_keys:
            emit(f"      • {k}")
        emit("   Executing malware here risks exfiltration of these keys. The machine that")
        emit("   detonates a sample must hold NO credentials. Remediate, then re-run:")
        emit("      1. Delete the repo's .env in this VM:   Remove-Item .env")
        emit("      2. Unset any exported vars, e.g.:        Remove-Item Env:OPENROUTER_API_KEY")
        emit("   (detonate needs no API key — it makes zero model calls.)")
        emit("   To override deliberately (NOT recommended): set ARGUS_DETONATE_ALLOW_KEYS=1")
        if result is not None:
            result.update({"blocked": True, "blocked_keys": live_keys})
        return "\n".join(lines)

    sample = (sample or "").strip()
    if not sample:
        emit("ERROR: sample path is required.")
        if result is not None:
            result.update({"error": "sample path is required"})
        return "\n".join(lines)
    sample_path = Path(sample).expanduser()
    if not sample_path.exists():
        emit(f"ERROR: no such file: {sample_path}")
        if result is not None:
            result.update({"error": f"no such file: {sample_path}"})
        return "\n".join(lines)

    timeout = int(timeout)
    sha = _sha256(sample_path)
    out_dir = _DYNAMIC_DIR / f"{sha[:16]}_{_timestamp()}"
    out_dir.mkdir(parents=True, exist_ok=True)

    emit("🛡 DYNAMIC ANALYSIS — executing sample in VM")
    emit(f"Sample: {sample_path}")
    emit(f"SHA256: {sha}")
    emit(f"Timeout: {timeout}s")
    emit(f"Output: {out_dir}")

    # Stage 1: Static identification (+ static YARA scan — never executes)
    emit("[1/6] Static identification...")
    static = _collect_sample_info(str(sample_path), out_dir)
    emit(f"  Type: {static.get('type', '?')}  Size: {static.get('size', '?')} bytes")
    try:
        from .. import yara_engine
        static["yara"] = yara_engine.scan_file(str(sample_path))
    except Exception:
        static["yara"] = []
    if static["yara"]:
        emit(f"  YARA: matched {len(static['yara'])} rule(s): {', '.join(static['yara'][:6])}")

    # Stage 2: Baseline snapshots (slow: reg query /s + dir /s /b)
    emit("[2/6] Baseline snapshots (registry + filesystem — this can take 30-60s)...")
    _registry_snapshot("before", out_dir)
    _filesystem_snapshot("before", out_dir, _snapshot_dirs())
    proc_before = _process_tree_snapshot()
    (out_dir / "processes_before.txt").write_text(proc_before, encoding="utf-8")
    emit("  registry + filesystem + process snapshots captured")

    # Stage 3: Start monitoring
    emit("[3/6] Starting monitoring probes...")
    fakenet = _start_fakenet()
    fn_val = os.environ.get("ARGUS_FAKENET", "").strip()
    if fn_val:
        if fakenet:
            emit("  FakeNet: active — answering C2 so a gated payload fires")
        else:
            fn_exe = "fakenet" if fn_val in ("1", "true", "yes") else fn_val
            if shutil.which(fn_exe) or os.path.exists(fn_exe):
                emit("  FakeNet: found but EXITED immediately — it needs Administrator "
                     "(WFP diverter) + a config: run the shell elevated and use "
                     "`fakenet.exe -c <config.ini>`. Payload may stay dormant.")
            else:
                emit("  FakeNet: NOT found on PATH — install FakeNet-NG. "
                     "Payload may stay dormant.")
    procmon = _start_procmon_capture(out_dir)
    if procmon.get("error"):
        emit(f"  Procmon: {procmon['error']} — behavioral telemetry will be MISSING "
             "(verdict falls back to static signals only).")
    else:
        emit(f"  Procmon: PID {procmon.get('pid', '?')} ({procmon.get('exe')}) "
             f"-> {procmon.get('log')}")
    iface = _pick_capture_iface()
    net_proc = _start_network_capture(out_dir, iface)
    emit(f"  Network: {'capturing on iface ' + iface + ' -> ' + str(out_dir / 'network.pcap') if net_proc else 'unavailable (install tshark / add it to PATH)'}")

    # Stage 4: Execute (silent until exit/timeout — watch the .pml grow instead)
    emit(f"[4/6] EXECUTING sample now — running up to {timeout}s. No new lines until it "
         f"exits or the timeout fires; watch the .pml grow or open Procmon live to follow.")
    exec_start = time.time()
    exec_result = _execute_sample(str(sample_path), min(timeout, _MAX_EXECUTION_SECONDS))
    elapsed = time.time() - exec_start
    if exec_result.get("executed"):
        emit(f"  ran for {elapsed:.1f}s, exit code: {exec_result.get('exit_code')}")
        if exec_result.get("killed_after_timeout"):
            emit("  ⚠ sample was forcefully killed after timeout")
    else:
        emit(f"  execution failed: {exec_result.get('error')}")

    # Stage 5: Stop monitoring
    emit("[5/6] Stopping monitoring (flushing procmon + pcap)...")
    _stop_procmon_capture(procmon)
    _stop_network_capture(net_proc)
    _stop_fakenet(fakenet)
    time.sleep(3)

    # Stage 6: After-snapshots + AUTOMATIC analysis (diffs + procmon + verdict)
    emit("[6/6] After-snapshots + analyzing (diffing registry/fs, parsing procmon)...")
    _registry_snapshot("after", out_dir)
    _filesystem_snapshot("after", out_dir, _snapshot_dirs()[:3])
    proc_after = _process_tree_snapshot()
    (out_dir / "processes_after.txt").write_text(proc_after, encoding="utf-8")

    struct = analyze_detonation(out_dir, static, exec_result)
    findings = _format_findings(struct)
    for ln in findings:
        emit(ln)

    # Persist the structured findings next to the artifacts so the panel and the
    # publish pipeline can read the verdict without re-parsing anything.
    try:
        (out_dir / "findings.json").write_text(json.dumps(struct, indent=2), encoding="utf-8")
    except OSError:
        pass

    # Auto-produce the full intel bundle (IOCs + Sigma) so every run is a
    # complete, shareable detection package — no manual `ioc`/`sigma` needed.
    bundle = write_intel_bundle(out_dir, struct, static)
    if bundle:
        emit(f"  intel bundle: {bundle['ioc_count']} IOC(s), {bundle['sigma_count']} "
             f"Sigma rule(s) -> iocs.json/csv" + (", sigma.yml" if bundle["sigma_count"] else ""))

    report = _generate_behavioral_report(sha, out_dir, static, exec_result, findings)
    emit("")
    emit("✅ analysis complete.")
    emit(f"  report: {report}")
    emit(f"  artifacts: {out_dir}")

    if result is not None:
        result.update({
            "out_dir": str(out_dir), "sha256": sha, "sample": str(sample_path),
            "report": report, "static": static, "exec": exec_result, **struct,
        })

    return cap("\n".join(lines), config.TOOL_OUTPUT_CAP * 3)


def reanalyze_run(out_dir, on_progress=None) -> dict:
    """Re-run the auto-analysis on an EXISTING run folder (no re-detonation).

    Salvages a run whose verdict came back INCONCLUSIVE because the procmon
    .pml wasn't converted in time — converts it now (reusing an existing CSV if
    present) and rewrites findings.json + KEY FINDINGS."""
    out_dir = Path(out_dir)

    def emit(line: str) -> None:
        if on_progress:
            try:
                on_progress(line)
            except Exception:
                pass

    info = out_dir / "sample_info.json"
    if not info.exists():
        emit(f"ERROR: {out_dir} is not a detonation run (no sample_info.json)")
        return {"error": "not a run dir"}
    static = json.loads(info.read_text(encoding="utf-8"))
    emit(f"Re-analyzing {out_dir.name}  (sample: {static.get('name', '?')})")
    pml = out_dir / "procmon.pml"
    if pml.exists():
        emit(f"Converting procmon log ({pml.stat().st_size / (1024*1024):.0f} MB — "
             "a large log can take a few minutes)...")
    struct = analyze_detonation(out_dir, static, {})
    for ln in _format_findings(struct):
        emit(ln)
    (out_dir / "findings.json").write_text(json.dumps(struct, indent=2), encoding="utf-8")
    emit(f"\nfindings.json updated -> {out_dir / 'findings.json'}")
    return struct


# ---------------------------------------------------------------------------
# tool
# ---------------------------------------------------------------------------
def make_dynamic_analysis() -> Tool:
    def handler(inp: dict) -> str:
        action = (inp.get("action") or "detonate").strip().lower()
        if action == "snapshot":
            return run_snapshot()
        return run_detonation(inp.get("sample"), int(inp.get("timeout", _MAX_EXECUTION_SECONDS)))

    return Tool(
        name="dynamic_analysis",
        description=(
            "DYNAMIC malware analysis — EXECUTES the sample in a controlled VM. "
            "Sets up Process Monitor, network capture, registry/filesystem snapshots, "
            "executes the sample with a timeout, then collects all behavioral telemetry. "
            "Generates a full behavioral report with process tree, network traffic, "
            "and system changes.\n\n"
            "⚠ VM ONLY. Use ONLY in an isolated Windows VM with host-only networking "
            "and a snapshot to revert. This tool ACTUALLY RUNS the malware.\n\n"
            "Actions:\n"
            "  'detonate' (default) — full behavioral analysis: baseline → execute → collect\n"
            "  'snapshot' — take baseline snapshots only (no execution, for differential analysis)"
        ),
        input_schema={
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["detonate", "snapshot"],
                    "description": "'detonate' for full analysis, 'snapshot' for baseline only.",
                },
                "sample": {
                    "type": "string",
                    "description": "Path to the malware sample to execute.",
                },
                "timeout": {
                    "type": "integer",
                    "description": f"Max execution seconds before forced kill (default {_MAX_EXECUTION_SECONDS}).",
                },
            },
            "required": ["sample"],
        },
        handler=handler,
    )
