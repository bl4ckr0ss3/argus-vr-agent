"""Static report generation for publishing findings to a website (e.g. GitHub
Pages). Produces a self-contained HTML page per finding (no build step, no
external assets), an index page, and a JSON feed. Pure stdlib.

The same structured view feeds the HTML report and could feed other channels;
it deliberately omits sections with no data so a report is accurate, not padded.
"""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone

SITE_TITLE = "0xblack.dev · Threat Intelligence"
SITE_TAG = "Automated malware analysis by ARGUS"

_VERDICT_LABEL = {
    "suspicious": ("SUSPICIOUS", "#e06c75"),
    "benign": ("BENIGN", "#98c379"),
    "inconclusive": ("INCONCLUSIVE", "#8b9bb4"),
}


def _uniq(seq):
    seen, out = [], []
    for x in seq or []:
        s = str(x).strip()
        if s and s not in seen:
            seen.append(s)
            out.append(s)
    return out


def finding_view(struct: dict) -> dict:
    """Structured, display-ready view of a finding (shared by HTML + feed)."""
    from .publish import _IOC_DENY, _CONF_BAND
    verdict = struct.get("verdict", "inconclusive")
    conf = struct.get("confidence", 0) or 0
    behaviour = {
        "persistence": _uniq(struct.get("persistence")),
        "children": _uniq(struct.get("spawned")),
        "drops": _uniq(struct.get("staged_payloads")),
        "network": _uniq(struct.get("net")),
    }
    pk = struct.get("packer")
    if isinstance(pk, dict):
        pk = pk.get("packer") or "detected"
    iocs = []
    try:
        from . import ioc as _ioc
        own = (struct.get("sha256") or "").lower()
        for cat, vals in (_ioc.extract_from(struct, struct.get("static")) or {}).items():
            for v in vals[:8]:
                low = str(v).lower()
                if low == own or low in _IOC_DENY:
                    continue
                iocs.append(_ioc.defang(v, _ioc._KIND.get(cat, cat)))
    except Exception:
        pass
    return {
        "sample": struct.get("sample") or (struct.get("sha256", "")[:16]),
        "sha256": struct.get("sha256", ""),
        "verdict": verdict,
        "confidence": conf,
        "confidence_band": _CONF_BAND(conf),
        "signals": struct.get("signals") or [],
        "attack": struct.get("attack") or [],
        "yara": struct.get("yara") or [],
        "packer": pk if struct.get("packed") else None,
        "entropy": struct.get("entropy"),
        "behaviour": behaviour,
        "iocs": iocs[:20],
        "vt": (struct.get("vt") or {}).get("summary"),
    }


def slug(struct: dict, ts: str = "") -> str:
    # sha-only so the report URL is deterministic from the hash alone (the VT
    # comment can link to it without knowing the publish date). ts is ignored.
    return (struct.get("sha256") or "nohash")[:16]


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------
_CSS = """
:root{--bg:#0b0d12;--panel:#12151c;--line:#232833;--ink:#c8ccd4;--dim:#7a8394;
--cyan:#56b6c2;--amber:#e5c07b;--rose:#e06c75;--green:#98c379;--purple:#c586c0}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.6 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
a{color:var(--cyan);text-decoration:none}a:hover{text-decoration:underline}
.wrap{max-width:860px;margin:0 auto;padding:32px 20px 80px}
.top{display:flex;align-items:center;gap:10px;border-bottom:1px solid var(--line);padding-bottom:14px;margin-bottom:26px}
.brand{font-weight:800;letter-spacing:.5px}.brand .x{color:var(--amber)}
.top .tag{color:var(--dim);font-size:13px;margin-left:auto}
h1{font-size:22px;margin:0 0 4px;word-break:break-all}
.badge{display:inline-block;padding:3px 11px;border-radius:999px;font-size:12px;font-weight:700;
letter-spacing:.5px;vertical-align:middle}
.meta{color:var(--dim);font-size:13px;margin:6px 0 24px}
.mono{font-family:ui-monospace,Consolas,monospace}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin:16px 0}
.card h2{font-size:14px;text-transform:uppercase;letter-spacing:.6px;color:var(--dim);margin:0 0 12px}
.kv{display:grid;grid-template-columns:130px 1fr;gap:6px 14px;font-size:14px}
.kv .k{color:var(--dim)}.kv .v{word-break:break-all}
ul.clean{list-style:none;margin:0;padding:0}ul.clean li{padding:3px 0;border-bottom:1px solid #171b23;word-break:break-all}
ul.clean li:last-child{border:0}
.attack{display:flex;flex-wrap:wrap;gap:8px}.attack .t{background:#181c25;border:1px solid var(--line);
border-radius:7px;padding:4px 10px;font-size:13px}.attack .t b{color:var(--purple)}
.pill{background:#181c25;border:1px solid var(--line);border-radius:7px;padding:3px 9px;font-size:12.5px;margin:2px;display:inline-block}
.disclaimer{color:var(--dim);font-size:12.5px;border-top:1px solid var(--line);margin-top:28px;padding-top:16px}
.foot{color:var(--dim);font-size:12.5px;margin-top:10px}
table{width:100%;border-collapse:collapse;font-size:14px}
td,th{text-align:left;padding:7px 10px;border-bottom:1px solid #171b23}th{color:var(--dim);font-weight:600}
tr:hover{background:#141821}
@media(prefers-color-scheme:light){:root{--bg:#f6f7f9;--panel:#fff;--line:#e3e6ea;--ink:#1a1d23;--dim:#5b6472}}
"""


def _e(s):
    return html.escape(str(s))


def report_html(struct: dict, generated: str) -> str:
    v = finding_view(struct)
    label, color = _VERDICT_LABEL.get(v["verdict"], (v["verdict"].upper(), "#8b9bb4"))
    b = v["behaviour"]
    sections = []

    kv = [("Verdict", f'<span class="badge" style="background:{color}22;color:{color}">{label}</span>'
           f' &nbsp; confidence <b>{v["confidence"]}%</b> ({_e(v["confidence_band"])})'),
          ("SHA-256", f'<span class="mono">{_e(v["sha256"])}</span>')]
    if v["packer"]:
        kv.append(("Packing", _e(v["packer"]) + (f' (entropy {_e(v["entropy"])})' if v["entropy"] else "")))
    if v["signals"]:
        kv.append(("Signals", _e(", ".join(v["signals"]))))
    if v["vt"]:
        kv.append(("VirusTotal", f'{_e(v["vt"])} &middot; '
                   f'<a href="https://www.virustotal.com/gui/file/{_e(v["sha256"])}" target="_blank" rel="noopener">view on VT</a>'))
    kvhtml = "".join(f'<div class="k">{k}</div><div class="v">{val}</div>' for k, val in kv)
    sections.append(f'<div class="card"><h2>Summary</h2><div class="kv">{kvhtml}</div></div>')

    sections.append('<div class="card"><h2>Methodology</h2><p style="margin:0">The sample was '
                    'executed in an isolated, instrumented Windows VM (host-only networking with '
                    'emulated C2 responses) while process, file-system, registry and network activity '
                    'were recorded. The verdict is derived by correlating observed runtime behaviour '
                    'with static indicators. No sample binary was uploaded or redistributed.</p></div>')

    beh = []
    for title, items in (("Persistence", b["persistence"]), ("Child processes", b["children"]),
                         ("Dropped files", b["drops"]), ("Network endpoints", b["network"])):
        if items:
            lis = "".join(f'<li class="mono">{_e(x)}</li>' for x in items[:20])
            beh.append(f'<h2>{title} ({len(items)})</h2><ul class="clean">{lis}</ul>')
    if not beh:
        beh.append('<p style="margin:0;color:var(--dim)">No high-confidence host or network side '
                   'effects were captured in this run (payload may be environment-gated or dormant).</p>')
    sections.append('<div class="card">' + "".join(beh) + '</div>')

    if v["attack"]:
        tags = "".join(f'<span class="t"><b>{_e(t.get("id"))}</b> {_e(t.get("name",""))}</span>'
                       for t in v["attack"][:12])
        sections.append(f'<div class="card"><h2>MITRE ATT&amp;CK</h2><div class="attack">{tags}</div></div>')

    if v["yara"]:
        pills = "".join(f'<span class="pill mono">{_e(y)}</span>' for y in v["yara"][:12])
        sections.append(f'<div class="card"><h2>YARA matches</h2>{pills}</div>')

    if v["iocs"]:
        lis = "".join(f'<li class="mono">{_e(i)}</li>' for i in v["iocs"])
        sections.append(f'<div class="card"><h2>Indicators of Compromise (defanged)</h2>'
                        f'<ul class="clean">{lis}</ul></div>')

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_e(v["sample"])} — {label} — {SITE_TITLE}</title>
<meta name="description" content="Automated malware triage: {_e(v["sample"])} assessed {label} ({v['confidence']}%).">
<style>{_CSS}</style></head><body><div class="wrap">
<div class="top"><span class="brand">0x<span class="x">black</span>.dev</span>
<span class="tag">{SITE_TAG}</span></div>
<a href="index.html" style="font-size:13px">&larr; all findings</a>
<h1 style="margin-top:12px">{_e(v["sample"])}</h1>
<div class="meta">Published {_e(generated)} · analysis by ARGUS</div>
{''.join(sections)}
<div class="disclaimer">This is an automated behavioural assessment shared for community awareness
and defensive purposes. It reflects heuristics over observed activity and should be independently
verified before operational use. Sample identifiers are provided for detection; no malware is hosted here.</div>
<div class="foot">Generated by <b>ARGUS</b> · 0xblack.dev</div>
</div></body></html>"""


def index_html(entries: list[dict]) -> str:
    rows = ""
    for e in entries:
        label, color = _VERDICT_LABEL.get(e["verdict"], (e["verdict"].upper(), "#8b9bb4"))
        rows += (f'<tr><td class="mono">{_e(e["date"])}</td>'
                 f'<td><a href="{_e(e["file"])}">{_e(e["sample"])}</a></td>'
                 f'<td><span class="badge" style="background:{color}22;color:{color}">{label}</span></td>'
                 f'<td>{e["confidence"]}%</td>'
                 f'<td class="mono" style="color:var(--dim)">{_e(e["sha256"][:16])}…</td></tr>')
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{SITE_TITLE}</title>
<meta name="description" content="{SITE_TAG} — public malware triage reports.">
<style>{_CSS}</style></head><body><div class="wrap">
<div class="top"><span class="brand">0x<span class="x">black</span>.dev</span>
<span class="tag">{SITE_TAG}</span></div>
<h1>Threat Intelligence Feed</h1>
<div class="meta">{len(entries)} published finding(s) · automated malware triage · <a href="feed.json">JSON feed</a></div>
<div class="card"><table><thead><tr><th>Date</th><th>Sample</th><th>Verdict</th><th>Conf.</th><th>SHA-256</th></tr></thead>
<tbody>{rows or '<tr><td colspan=5 style="color:var(--dim)">No findings yet.</td></tr>'}</tbody></table></div>
<div class="foot">Generated by <b>ARGUS</b></div>
</div></body></html>"""


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
