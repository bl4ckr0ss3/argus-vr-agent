"""Fetch community YARA rulesets and collect them (stdlib only).

Pulls rules from a curated set of reputable public repos into a STAGING area
that the scanner does NOT load by default:

    config.YARA_RULES_DIR/community/<source>/*.yar

A source only contributes to scanning after you `enable` it (a deliberate trust
decision) — same review gate as generated rules. Enabling flips a flag; the
engine then includes that source's rules. Nothing is executed; rules are text.

GitHub's unauthenticated API allows ~60 requests/hour. Set GITHUB_TOKEN in the
environment (host only) to raise that if you fetch many sources.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path

import config

# Curated, reputable sources. Licenses vary per repo — check each before
# redistributing; for local detection use they're fine.
SOURCES = {
    "signature-base": {
        "owner": "Neo23x0", "repo": "signature-base", "path": "yara", "ref": "master",
        "desc": "Florian Roth / Nextron — high-quality APT & malware rules (LOKI/THOR)"},
    "yara-rules": {
        "owner": "Yara-Rules", "repo": "rules", "path": "malware", "ref": "master",
        "desc": "Community YARA-Rules project — broad malware coverage"},
    "reversinglabs": {
        "owner": "reversinglabs", "repo": "reversinglabs-yara-rules", "path": "yara", "ref": "develop",
        "desc": "ReversingLabs curated detection rules"},
    "elastic": {
        "owner": "elastic", "repo": "protections-artifacts", "path": "yara/rules", "ref": "main",
        "desc": "Elastic Security public YARA rules"},
}


def _community_dir() -> Path:
    return config.YARA_RULES_DIR / "community"


def _enabled_file() -> Path:
    return _community_dir() / "enabled.json"


def _load_enabled() -> list[str]:
    try:
        return list(json.loads(_enabled_file().read_text(encoding="utf-8")))
    except Exception:
        return []


def _save_enabled(names: list[str]) -> None:
    _community_dir().mkdir(parents=True, exist_ok=True)
    _enabled_file().write_text(json.dumps(sorted(set(names)), indent=2), encoding="utf-8")


def _gh_headers() -> dict:
    h = {"User-Agent": "ARGUS-VR-Agent", "Accept": "application/vnd.github+json"}
    tok = os.environ.get("GITHUB_TOKEN", "").strip()
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h


def _http_get(url: str, headers: dict | None = None, timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def list_sources() -> list[dict]:
    enabled = set(_load_enabled())
    fetched = fetched_summary()
    return [{"name": n, "desc": s["desc"], "repo": f"{s['owner']}/{s['repo']}",
             "enabled": n in enabled, "fetched": fetched.get(n, 0)}
            for n, s in SOURCES.items()]


def fetch(name: str, limit: int = 400) -> dict:
    """Download a source's top-level .yar files into its staging dir."""
    src = SOURCES.get(name)
    if not src:
        return {"error": f"unknown source '{name}' — see: python run.py rules --sources"}
    api = (f"https://api.github.com/repos/{src['owner']}/{src['repo']}"
           f"/contents/{src['path']}?ref={src['ref']}")
    try:
        items = json.loads(_http_get(api, _gh_headers()))
    except urllib.error.HTTPError as e:
        if e.code == 403:
            return {"error": "GitHub rate limit hit — set GITHUB_TOKEN and retry"}
        return {"error": f"HTTP {e.code} listing {name}"}
    except Exception as e:
        return {"error": f"cannot reach GitHub: {e}"}
    if not isinstance(items, list):
        return {"error": "unexpected API response (rate-limited? set GITHUB_TOKEN)"}

    dest = _community_dir() / name
    dest.mkdir(parents=True, exist_ok=True)
    fetched, skipped = [], 0
    for it in items:
        if it.get("type") != "file":
            continue
        nm = it.get("name", "")
        if not nm.endswith((".yar", ".yara")):
            continue
        if len(fetched) >= limit:
            break
        url = it.get("download_url")
        if not url:
            skipped += 1
            continue
        try:
            (dest / nm).write_bytes(_http_get(url))
            fetched.append(nm)
        except Exception:
            skipped += 1
    return {"ok": True, "source": name, "dir": str(dest),
            "fetched": fetched, "count": len(fetched), "skipped": skipped}


def fetched_summary() -> dict:
    out = {}
    base = _community_dir()
    if not base.exists():
        return out
    for d in base.iterdir():
        if d.is_dir():
            out[d.name] = len(list(d.glob("*.yar"))) + len(list(d.glob("*.yara")))
    return out


def enable(name: str) -> dict:
    if name not in SOURCES:
        return {"error": f"unknown source '{name}'"}
    if not (_community_dir() / name).exists():
        return {"error": f"'{name}' not fetched yet — run: python run.py rules --fetch {name}"}
    en = _load_enabled()
    if name not in en:
        en.append(name)
        _save_enabled(en)
    return {"ok": True, "enabled": name, "active_sources": _load_enabled()}


def disable(name: str) -> dict:
    en = _load_enabled()
    if name in en:
        en.remove(name)
        _save_enabled(en)
    return {"ok": True, "disabled": name, "active_sources": _load_enabled()}


def active_community_files() -> list[Path]:
    """Rule files from ENABLED community sources — included by the scanner."""
    out: list[Path] = []
    for name in _load_enabled():
        d = _community_dir() / name
        if d.exists():
            out += sorted(d.rglob("*.yar")) + sorted(d.rglob("*.yara"))
    return out
