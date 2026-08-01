"""Diff two dynamic-analysis runs to isolate C2-gated (malicious) behavior.

The "both, in order" detonation gives two runs of the same sample:
  A = untouched (FakeNet answering the C2 -> payload fires)
  B = C2 sinkholed (phase2_hosts.txt -> C2 dead, only legit paths survive)

Behavior in A's deltas but *absent* from B's is behavior that only happens when
the C2 is reachable — i.e. the malicious, gated component. Behavior in both is
the app's legitimate functionality. That difference is the whole point of the
exercise, computed instead of eyeballed.

Consumes what ARGUS's `detonate` writes to runs/dynamic/<hash>_<ts>/:
  files_before.txt / files_after.txt        (plain text — always present)
  registry_before.txt / registry_after.txt  (plain text — always present)
  network.pcap                              (optional — needs tshark on PATH)

Pure-python for the text artifacts (safe to run/test on the host); shells out to
tshark only if a pcap and tshark are both present, and degrades gracefully.

CLI:  python -m argus.intel.rundiff <run_A_untouched> <run_B_sinkholed> [--out DIR]
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

_WINPATH = re.compile(r"^[A-Za-z]:\\")


def _read(run_dir: Path, name: str) -> str:
    p = run_dir / name
    return p.read_text(encoding="utf-8", errors="ignore") if p.exists() else ""


def _paths(text: str) -> set[str]:
    """Extract absolute file paths from a `dir /s /b` snapshot."""
    return {ln.strip() for ln in text.splitlines() if _WINPATH.match(ln.strip())}


def _reg_lines(text: str) -> set[str]:
    """Meaningful lines from a `reg query /s` snapshot (skip section headers)."""
    out = set()
    for ln in text.splitlines():
        s = ln.strip()
        if not s or s.startswith("===") or s.startswith("---"):
            continue
        out.add(s)
    return out


def _delta(run_dir: Path, before: str, after: str, parser) -> set[str]:
    """What parser() sees in `after` but not `before` (things the run created)."""
    b = parser(_read(run_dir, before))
    a = parser(_read(run_dir, after))
    return a - b


def _net_http(run_dir: Path) -> set[str] | None:
    """`host uri` for HTTP requests that actually completed. None if unavailable.

    Sinkholing sends the C2 to 0.0.0.0, so its DNS query still fires in run B but
    the TCP/HTTP layer never forms — meaning a completed HTTP request to the C2
    shows up only in the untouched run. That makes http.host the right field to
    diff on (DNS names alone would appear in both runs)."""
    pcap = run_dir / "network.pcap"
    tshark = shutil.which("tshark")
    if not pcap.exists() or not tshark:
        return None
    try:
        out = subprocess.run(
            [tshark, "-r", str(pcap), "-Y", "http.request",
             "-T", "fields", "-e", "http.host", "-e", "http.request.uri"],
            capture_output=True, text=True, timeout=120, errors="ignore",
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    hosts = set()
    for ln in out.splitlines():
        parts = ln.split("\t")
        host = parts[0].strip() if parts else ""
        uri = parts[1].strip() if len(parts) > 1 else ""
        if host:
            hosts.add(f"{host}{uri}")
    return hosts


def _run_deltas(run_dir: Path) -> dict[str, set[str] | None]:
    return {
        "files": _delta(run_dir, "files_before.txt", "files_after.txt", _paths),
        "registry": _delta(run_dir, "registry_before.txt", "registry_after.txt", _reg_lines),
        "http": _net_http(run_dir),
    }


def compare(dir_a: Path, dir_b: Path) -> dict:
    """Malicious-only = present in A's deltas, absent from B's."""
    a, b = _run_deltas(dir_a), _run_deltas(dir_b)
    result = {}
    for k in ("files", "registry", "http"):
        av, bv = a[k], b[k]
        if av is None or bv is None:
            result[k] = {"available": False, "malicious": [], "shared": []}
            continue
        result[k] = {
            "available": True,
            "malicious": sorted(av - bv),   # only when C2 reachable
            "shared": sorted(av & bv),      # legit app behavior
        }
    return result


def render(result: dict, dir_a: Path, dir_b: Path, out_dir: Path | None) -> str:
    lines = ["# Malicious-behavior diff (C2-gated delta)", "",
             f"- untouched run (A): `{dir_a}`",
             f"- sinkholed run (B): `{dir_b}`", "",
             "Items below fired ONLY when the C2 was reachable — the gated payload.",
             ""]
    labels = {"files": "Files created", "registry": "Registry changes",
              "http": "HTTP endpoints contacted"}
    for k in ("http", "files", "registry"):
        r = result[k]
        lines.append(f"## {labels[k]}")
        if not r["available"]:
            note = "no pcap / tshark not on PATH" if k == "http" else "snapshots missing"
            lines.append(f"  _(unavailable — {note})_\n")
            continue
        mal = r["malicious"]
        lines.append(f"  MALICIOUS-ONLY ({len(mal)}):")
        lines += [f"    ! {x}" for x in mal] or ["    (none)"]
        lines.append(f"  shared/legit ({len(r['shared'])}) — present in both runs\n")
    text = "\n".join(lines) + "\n"
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "malicious_diff.md").write_text(text, encoding="utf-8")
    return text


def main(argv: list[str] | None = None) -> None:
    argv = argv if argv is not None else sys.argv[1:]
    pos = [a for a in argv if not a.startswith("--")]
    if len(pos) < 2:
        print("usage: python -m argus.intel.rundiff <run_A_untouched> <run_B_sinkholed> [--out DIR]")
        raise SystemExit(2)
    dir_a, dir_b = Path(pos[0]), Path(pos[1])
    out_dir = Path(argv[argv.index("--out") + 1]) if "--out" in argv else None
    result = compare(dir_a, dir_b)
    print(render(result, dir_a, dir_b, out_dir))


if __name__ == "__main__":
    main()
