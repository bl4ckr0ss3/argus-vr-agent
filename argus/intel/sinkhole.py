"""Turn a noisy static-IOC dump into an actionable network plan.

String-extracted IOC lists from a PE are mostly garbage — HTML/DTD boilerplate,
JS builtins, and (for Rust binaries) crate source paths that look like domains
(`app.rs`, `arcs.rs`). This module classifies every host-like IOC into three
buckets so you can drive a controlled detonation:

  - SUSPECT  : plausible real FQDN, not a known-benign vendor  -> the C2 / exfil
               candidates. ANSWER these in FakeNet (Phase 1, coax the payload);
               SINKHOLE these in the VM hosts file (Phase 2, kill C2, keep app).
  - BENIGN   : known-good vendor infra the app legitimately needs (Hyperliquid,
               Microsoft WebView2, crates.io, etc). Let these through.
  - NOISE    : source paths / code identifiers / markup -> ignore.

Pure text processing — never touches the sample. Safe to run on the host.

CLI:  python -m argus.intel.sinkhole <ioc_report.txt> [--out DIR]
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

# Vendor infra the app legitimately talks to — let it through, never sinkhole.
_BENIGN_SUFFIXES = {
    "hyperliquid.xyz", "hyperliquid-testnet.xyz",
    "microsoft.com", "windows.com",
    "docs.rs", "crates.io", "rust-lang.org",
    "github.com", "githubusercontent.com",
    "w3.org", "whatwg.org",
    "openssl.org", "mozilla.org",
    "godaddy.com", "ssl.com",  # cert-chain strings, not C2
}

# Real public suffixes we accept as "this is actually a domain". `.rs` is
# deliberately excluded: in a Rust binary `foo.rs` is a source file, not Serbia.
_REAL_TLDS = {
    "com", "net", "org", "io", "xyz", "cloud", "men", "co", "dev", "app",
    "me", "info", "biz", "online", "site", "live", "top", "gg", "tk",
    "ru", "cn", "us", "uk", "de", "nl", "click", "shop", "fun", "cyou",
}

# Substrings that mark an entry as extraction noise (code / markup / builtins).
_NOISE_MARKERS = (
    ".rs", ".toml", "::", "/src/", ".dtd", "px;", "text-align",
    "encodeuri", "stringify", "prototype", "addeventlistener",
    "w3.org", "html4", "-compatible",
)
_JS_BUILTIN = re.compile(r"^(object|math|json|array|explorer|window|document)\.", re.I)
_FQDN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.I)


def _hosts(report_text: str) -> list[str]:
    """Pull the embedded IOC JSON (or scrape host-like tokens) from the report."""
    m = re.search(r"\{.*\}", report_text, re.S)
    hosts: list[str] = []
    if m:
        try:
            data = json.loads(m.group(0))
            for key in ("domain", "url", "ipv4"):
                for v in data.get(key, []):
                    # strip scheme + path so "http://a.b/c" -> "a.b"
                    tok = re.sub(r"^\w+://", "", str(v)).split("/")[0].strip()
                    if tok:
                        hosts.append(tok.lower())
        except json.JSONDecodeError:
            pass
    return sorted(set(hosts))


def _tld(host: str) -> str:
    return host.rsplit(".", 1)[-1] if "." in host else ""


def _is_noise(host: str) -> bool:
    if any(mark in host for mark in _NOISE_MARKERS):
        return True
    if _JS_BUILTIN.match(host):
        return True
    if not _FQDN.match(host):
        return True
    if _tld(host) not in _REAL_TLDS:
        return True
    return False


def _is_benign(host: str) -> bool:
    return any(host == s or host.endswith("." + s) for s in _BENIGN_SUFFIXES)


def classify(report_text: str) -> dict[str, list[str]]:
    ipv4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    buckets: dict[str, list[str]] = {"suspect": [], "benign": [], "noise": []}
    for host in _hosts(report_text):
        if ipv4.match(host):
            # 16.15.14.13 / 20.19.18.17 in this sample are sequential dummies.
            octs = [int(o) for o in host.split(".")]
            (buckets["noise"] if octs == sorted(octs) else buckets["suspect"]).append(host)
        elif _is_benign(host):
            buckets["benign"].append(host)
        elif _is_noise(host):
            buckets["noise"].append(host)
        else:
            buckets["suspect"].append(host)
    return buckets


def render(buckets: dict[str, list[str]], out_dir: Path) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    suspect, benign = buckets["suspect"], buckets["benign"]

    # Phase 2 hosts file: sinkhole C2, leave benign vendor infra untouched.
    hosts = ["# Phase 2 sinkhole — kill C2, keep the app's legit endpoints.",
             "# Copy into C:\\Windows\\System32\\drivers\\etc\\hosts in the VM.",
             "# 0.0.0.0 = dead. Benign vendor domains are intentionally NOT listed."]
    hosts += [f"0.0.0.0 {h}" for h in suspect if not re.match(r"^\d", h)]
    hosts_path = out_dir / "phase2_hosts.txt"
    hosts_path.write_text("\n".join(hosts) + "\n", encoding="utf-8")

    # Phase 1 FakeNet allowlist: the domains to ANSWER so the payload fires.
    fnet = ["# Phase 1 — point FakeNet-NG DNS/HTTP at these to coax the payload.",
            "# These are the anti-analysis / exfil candidates to respond TO:"]
    fnet += suspect or ["# (no suspect hosts found)"]
    fnet_path = out_dir / "phase1_fakenet_answer.txt"
    fnet_path.write_text("\n".join(fnet) + "\n", encoding="utf-8")

    def _lines(items: list[str]) -> list[str]:
        return [f"  - {h}" for h in items] if items else ["  (none)"]

    report = ["# IOC network plan", "",
              f"## SUSPECT ({len(suspect)}) — C2 / exfil candidates",
              *_lines(suspect), "",
              f"## BENIGN ({len(benign)}) — legit app infra, let through",
              *_lines(benign), "",
              f"## NOISE ({len(buckets['noise'])}) — ignored extraction junk"]
    report_path = out_dir / "network_plan.md"
    report_path.write_text("\n".join(report) + "\n", encoding="utf-8")
    return {"hosts": hosts_path, "fakenet": fnet_path, "report": report_path}


def main(argv: list[str] | None = None) -> None:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print("usage: python -m argus.intel.sinkhole <ioc_report.txt> [--out DIR]")
        raise SystemExit(2)
    src = Path(argv[0])
    out_dir = Path(argv[argv.index("--out") + 1]) if "--out" in argv else src.parent / "netplan"
    buckets = classify(src.read_text(encoding="utf-8", errors="ignore"))
    paths = render(buckets, out_dir)
    print(f"SUSPECT: {buckets['suspect']}")
    print(f"BENIGN : {buckets['benign']}")
    print(f"NOISE  : {len(buckets['noise'])} entries")
    for label, p in paths.items():
        print(f"  {label:8} -> {p}")


if __name__ == "__main__":
    main()
