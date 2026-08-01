"""IOC extraction + export — turn a detonation into shareable threat intel.

Pulls indicators out of a run's structured findings (and static info): file
hashes, C2 IPs, domains, URLs, dropped files, persistence keys. Deduplicates,
drops lab/local noise, and can DEFANG for safe sharing (hxxp://, 1[.]2[.]3[.]4).

Exports CSV (for humans) and JSON (for tools / the publish pipeline).
Pure-function core (`extract_from`) so it's fully testable.
"""
from __future__ import annotations

import csv
import io
import json
import re
from pathlib import Path

_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL = re.compile(r"https?://[^\s\"'<>]+", re.I)
# Last label a file, not a domain — keep these from being misread as domains.
_NOT_TLD = {"exe", "dll", "sys", "dat", "tmp", "log", "bin", "ini", "cfg", "db", "efi"}
_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I)


def _is_public_ip(ip: str) -> bool:
    try:
        o = [int(x) for x in ip.split(".")]
    except ValueError:
        return False
    if len(o) != 4 or any(not 0 <= x <= 255 for x in o):
        return False
    a, b = o[0], o[1]
    if a in (0, 127, 255) or a >= 224:            # this/loopback/broadcast/multicast
        return False
    if a == 10 or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31):  # RFC1918
        return False
    if a == 169 and b == 254:                     # link-local
        return False
    return True


def extract_from(struct: dict, static: dict | None = None) -> dict:
    """Pure IOC extraction from a findings struct (+ optional static info)."""
    static = static or {}
    iocs = {"hashes": [], "ips": [], "domains": [], "urls": [],
            "files": [], "registry": [], "mutexes": []}

    # hashes — the sample + any dropped-file hashes carried in static
    h = static.get("hashes") or {}
    for k in ("sha256", "sha1", "md5"):
        if h.get(k):
            iocs["hashes"].append(h[k])
    if struct.get("sha256"):
        iocs["hashes"].append(struct["sha256"])

    # structured behavioral fields
    iocs["files"] += list(struct.get("staged_payloads") or [])
    iocs["registry"] += list(struct.get("persistence") or [])

    # network context — scan ONLY network-ish sources so file paths don't get
    # misread as domains
    st_iocs = static.get("iocs") or {}
    for key in ("urls", "domains", "ips", "mutexes"):
        iocs[key] += list(st_iocs.get(key) or [])
    net_text = "\n".join(str(x) for x in
                         (list(struct.get("net") or []) + list(struct.get("spawned") or [])))
    for u in _URL.findall(net_text):
        iocs["urls"].append(u.rstrip(".,);'\""))
    for ip in _IP.findall(net_text):
        if _is_public_ip(ip):
            iocs["ips"].append(ip)
    for d in _DOMAIN.findall(net_text):
        dl = d.lower()
        if dl.rsplit(".", 1)[-1] in _NOT_TLD:
            continue
        if dl.endswith((".local", ".invalid", ".arpa")):
            continue
        iocs["domains"].append(dl)

    for k in iocs:
        iocs[k] = sorted(set(iocs[k]))
    return iocs


def defang(value: str, kind: str) -> str:
    if kind == "url":
        return value.replace("http", "hxxp", 1).replace(".", "[.]")
    if kind in ("ip", "domain"):
        return value.replace(".", "[.]")
    return value


_KIND = {"ips": "ip", "domains": "domain", "urls": "url", "hashes": "hash",
         "files": "file", "registry": "registry", "mutexes": "mutex"}


def to_rows(iocs: dict, do_defang: bool = False) -> list[tuple[str, str]]:
    rows = []
    for cat, values in iocs.items():
        kind = _KIND.get(cat, cat)
        for v in values:
            rows.append((kind, defang(v, kind) if do_defang else v))
    return rows


def to_csv(iocs: dict, do_defang: bool = False) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["type", "indicator"])
    for kind, v in to_rows(iocs, do_defang):
        w.writerow([kind, v])
    return buf.getvalue()


def extract_run(run_dir: str) -> dict:
    """Load a run folder's findings.json + sample_info.json and extract IOCs."""
    p = Path(run_dir)
    fj = p / "findings.json"
    if not fj.exists():
        return {"error": f"no findings.json in {p}"}
    struct = json.loads(fj.read_text(encoding="utf-8"))
    info = p / "sample_info.json"
    static = json.loads(info.read_text(encoding="utf-8")) if info.exists() else {}
    return {"ok": True, "iocs": extract_from(struct, static), "run": str(p)}
