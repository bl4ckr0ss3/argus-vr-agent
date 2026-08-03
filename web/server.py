"""ARGUS web console — zero-dependency stdlib HTTP server.

No Flask, no install: just http.server + threads, so it runs under whatever
interpreter has `anthropic`. Serves a single-page console and streams the
agent's reasoning + tool calls to the browser over Server-Sent Events.

Routes
  GET  /                     -> the console (web/static/index.html)
  GET  /api/stats            -> corpus / tools / model / runs summary  (no key)
  POST /api/retrieve         -> BM25 RAG results for {query, k}         (no key)
  GET  /api/hunt?task=&mode= -> SSE stream of agent events              (needs key)
  GET  /api/runs             -> list saved run transcripts
  GET  /api/run?name=        -> one saved run transcript

Run:  python run.py web   (or)   python web/server.py
"""
from __future__ import annotations

import hmac
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import re  # noqa: E402

import config  # noqa: E402
from argus.rag import BM25Index  # noqa: E402
from argus.llm import backend_status  # noqa: E402

STATIC = Path(__file__).resolve().parent / "static"

# --- shared, lazily-built state -------------------------------------------
_index: BM25Index | None = None
_agents: dict = {}          # mode -> agent
_agent_errs: dict = {}      # mode -> error string
_lock = threading.Lock()
# Collaboration state
_active_collab = None       # current Collaboration instance
_collab_user_queue: list[str] = []  # messages from Muhammed to inject


def get_index() -> BM25Index:
    global _index
    with _lock:
        if _index is None:
            _index = BM25Index.from_corpus(config.CORPUS_FILE)
        return _index


def get_agent(mode: str = "hunt"):
    """Build (and cache) an Argus agent per mode. Returns (agent, error)."""
    with _lock:
        if mode in _agents or mode in _agent_errs:
            return _agents.get(mode), _agent_errs.get(mode)
        try:
            from argus.agent import Argus
            _agents[mode] = Argus(verbose=False, mode=mode)
        except Exception as e:
            _agent_errs[mode] = f"{type(e).__name__}: {e}"
        return _agents.get(mode), _agent_errs.get(mode)


def _load_dotenv() -> None:
    env = ROOT / ".env"
    if not env.exists():
        return
    import os
    for line in env.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())


def _benchmark_count() -> int:
    p = config.BENCHMARK_FILE
    if not p.exists():
        return 0
    return sum(1 for line in p.read_text(encoding="utf-8").splitlines() if line.strip())


def _clean_cell(s: str) -> str:
    s = re.sub(r"\[\[([^\]|]+)\|([^\]]+)\]\]", r"\2", s)   # [[a|b]] -> b
    s = re.sub(r"\[\[([^\]]+)\]\]", r"\1", s)               # [[a]]   -> a
    return s.replace("**", "").replace("`", "").strip()


def parse_targets() -> dict:
    """Parse the main markdown table in the vault's Targets.md into rows."""
    p = config.VR_DIR / "Targets.md"
    if not p.exists():
        return {"exists": False, "path": str(p), "targets": []}
    lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
    header_idx = None   # {key: column index}
    rows = []
    for raw in lines:
        line = raw.strip()
        if not line.startswith("|"):
            header_idx = None   # a table ended
            continue
        # collapse [[a|b]] so internal pipes don't break the split
        line = re.sub(r"\[\[([^\]|]+)\|([^\]]+)\]\]", r"[[\2]]", line)
        cells = [c.strip() for c in line.strip("|").split("|")]
        if set("".join(cells)) <= set("-: "):   # separator row
            continue
        if header_idx is None:
            low = [c.lower() for c in cells]
            joined = " ".join(low)
            if "target" in joined and "status" in joined:   # the main table only
                def find(kw):
                    for i, c in enumerate(low):
                        if kw in c:
                            return i
                    return None
                header_idx = {
                    "target": find("target"), "version": find("version"),
                    "status": find("status"), "surface": find("surface"),
                    "questions": find("question"), "notes": find("note"),
                }
            continue
        get = lambda k: _clean_cell(cells[header_idx[k]]) if header_idx.get(k) is not None and header_idx[k] < len(cells) else ""
        tgt = get("target")
        if tgt:
            rows.append({
                "target": tgt, "version": get("version"), "status": get("status").lower(),
                "surface": get("surface"), "questions": get("questions"), "notes": get("notes"),
            })
    return {"exists": True, "path": str(p), "targets": rows}


class Handler(BaseHTTPRequestHandler):
    server_version = "ARGUS/0.1"

    def log_message(self, fmt, *args):  # quieter console
        pass

    # --- helpers -----------------------------------------------------------
    def _json(self, obj, status=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: Path, ctype: str, cookie: str | None = None):
        if not path.exists():
            self._json({"error": "not found"}, 404)
            return
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    # --- auth --------------------------------------------------------------
    def _authed(self) -> bool:
        """True if the request is authorized. When config.WEB_TOKEN is unset,
        auth is disabled (single-user localhost dev mode). Otherwise the token
        must arrive via Authorization: Bearer, ?token=, or the argus_token cookie."""
        token = config.WEB_TOKEN
        if not token:
            return True
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer ") and hmac.compare_digest(auth[7:], token):
            return True
        q = parse_qs(urlparse(self.path).query).get("token", [""])[0]
        if q and hmac.compare_digest(q, token):
            return True
        for part in (self.headers.get("Cookie", "") or "").split(";"):
            part = part.strip()
            if part.startswith("argus_token=") and hmac.compare_digest(part[12:], token):
                return True
        return False

    # --- GET ---------------------------------------------------------------
    def do_GET(self):
        if not self._authed():
            return self._json({"error": "unauthorized — append ?token=<ARGUS_WEB_TOKEN>"}, 401)
        parsed = urlparse(self.path)
        route = parsed.path
        qs = parse_qs(parsed.query)

        if route == "/" or route == "/index.html":
            # On the first authed visit (?token=…), drop a cookie so subsequent
            # API/SSE calls authenticate without the token in every URL.
            cookie = None
            if config.WEB_TOKEN and qs.get("token", [""])[0]:
                cookie = f"argus_token={config.WEB_TOKEN}; Path=/; HttpOnly; SameSite=Strict"
            return self._send_file(STATIC / "index.html", "text/html; charset=utf-8", cookie=cookie)
        if route == "/api/stats":
            return self._stats()
        if route == "/api/targets":
            return self._json(parse_targets())
        if route == "/api/progression":
            return self._progression()
        if route == "/api/workflow":
            return self._workflow_status()
        if route == "/api/devroom":
            return self._devroom()
        if route == "/panel" or route == "/findings":
            cookie = None
            if config.WEB_TOKEN and qs.get("token", [""])[0]:
                cookie = f"argus_token={config.WEB_TOKEN}; Path=/; HttpOnly; SameSite=Strict"
            return self._send_file(STATIC / "findings.html", "text/html; charset=utf-8", cookie=cookie)
        if route == "/re" or route == "/reverse":
            cookie = None
            if config.WEB_TOKEN and qs.get("token", [""])[0]:
                cookie = f"argus_token={config.WEB_TOKEN}; Path=/; HttpOnly; SameSite=Strict"
            return self._send_file(STATIC / "re.html", "text/html; charset=utf-8", cookie=cookie)
        if route == "/pipeline" or route == "/ops":
            cookie = None
            if config.WEB_TOKEN and qs.get("token", [""])[0]:
                cookie = f"argus_token={config.WEB_TOKEN}; Path=/; HttpOnly; SameSite=Strict"
            return self._send_file(STATIC / "pipeline.html", "text/html; charset=utf-8", cookie=cookie)
        if route.startswith("/api/re/"):
            return self._re_get(route, qs)
        if route == "/api/publish/drafts":
            from argus import publish
            try:
                lim = int(qs.get("limit", ["300"])[0])
            except ValueError:
                lim = 300
            return self._json({"drafts": publish.list_drafts(limit=lim)})
        if route == "/api/publish/all/status":
            from argus import publish
            return self._json(publish.batch_status())
        if route == "/api/autopublish/status":
            from argus import autopublish
            return self._json(autopublish.status())
        if route == "/api/jobs":
            from argus import jobs
            return self._json({"types": jobs.job_types(), "jobs": jobs.list_jobs()})
        if route == "/api/job":
            from argus import jobs
            j = jobs.get(qs.get("id", [""])[0])
            return self._json(j or {"error": "no such job"}, 200 if j else 404)
        if route == "/api/pipeline":
            return self._pipeline()
        if route == "/api/runs":
            return self._runs()
        if route == "/api/run":
            return self._run_detail(qs.get("name", [""])[0])
        if route == "/api/hunt":
            return self._sse_hunt(qs)
        if route == "/api/collab/sessions":
            return self._collab_sessions()
        if route == "/api/collab/session":
            return self._collab_session(qs.get("name", [""])[0])
        if route == "/api/collab/stream":
            return self._sse_collab(qs)
        return self._json({"error": f"no route {route}"}, 404)

    # --- POST --------------------------------------------------------------
    def do_POST(self):
        if not self._authed():
            return self._json({"error": "unauthorized"}, 401)
        parsed = urlparse(self.path)
        if parsed.path in ("/api/retrieve", "/api/upload", "/api/static/analyze", "/api/collab/start", "/api/collab/message", "/api/collab/stop", "/api/jobs", "/api/publish/approve", "/api/publish/send", "/api/publish/all", "/api/autopublish/toggle", "/api/autopublish/scan"):
            length = int(self.headers.get("Content-Length", 0))
            if length > config.MAX_UPLOAD_BYTES + 2_000_000:
                return self._json({"error": "payload too large"}, 413)
            try:
                payload = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                return self._json({"error": "bad json"}, 400)
            if parsed.path == "/api/publish/approve":
                from argus import publish
                return self._json(publish.approve(payload.get("draft", "")))
            if parsed.path == "/api/publish/send":
                from argus import publish
                return self._json(publish.publish(
                    payload.get("draft", ""), payload.get("targets", []),
                    confirm=bool(payload.get("confirm")), force=bool(payload.get("force"))))
            if parsed.path == "/api/publish/all":
                from argus import publish
                return self._json(publish.start_batch(
                    payload.get("targets", ["vt"]), confirm=bool(payload.get("confirm"))))
            if parsed.path == "/api/autopublish/toggle":
                from argus import autopublish
                return self._json(autopublish.start() if payload.get("on") else autopublish.stop())
            if parsed.path == "/api/autopublish/scan":
                from argus import autopublish
                return self._json(autopublish.scan_once(dry=bool(payload.get("dry"))))
            if parsed.path == "/api/jobs":
                from argus import jobs
                return self._json(jobs.submit(payload.get("type", ""), payload.get("params", {})))
            if parsed.path == "/api/retrieve":
                return self._retrieve(payload)
            if parsed.path == "/api/upload":
                return self._upload(payload)
            if parsed.path == "/api/static/analyze":
                return self._static_analyze(payload)
            if parsed.path == "/api/collab/start":
                return self._sse_collab_start(payload)
            if parsed.path == "/api/collab/message":
                return self._collab_message(payload)
            if parsed.path == "/api/collab/stop":
                return self._collab_stop()
        if parsed.path in ("/api/re/load", "/api/re/asm", "/api/re/ask"):
            length = int(self.headers.get("Content-Length", 0))
            if length > config.MAX_UPLOAD_BYTES + 2_000_000:
                return self._json({"error": "payload too large"}, 413)
            try:
                payload = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                return self._json({"error": "bad json"}, 400)
            return self._re_post(parsed.path, payload)
        return self._json({"error": "no route"}, 404)

    # --- reverse-engineering workspace ------------------------------------
    def _re_get(self, route: str, qs: dict):
        from argus import re as remod
        sid = qs.get("id", [""])[0]

        def _addr():
            v = qs.get("addr", ["0"])[0]
            try:
                return int(v, 0)
            except ValueError:
                return 0

        if route == "/api/re/status":
            try:
                from argus.re import ai as _reai
                have_ai = _reai._ready()
            except Exception:
                have_ai = False
            return self._json({"have_capstone": remod.HAVE_CAPSTONE,
                               "have_keystone": remod.HAVE_KEYSTONE, "have_ai": have_ai})
        sess = remod.get_session(sid)
        if sess is None:
            return self._json({"error": "no such session — load a binary first"}, 404)
        if route == "/api/re/summary":
            return self._json(sess.summary())
        if route == "/api/re/sections":
            return self._json({"sections": sess.sections()})
        if route == "/api/re/symbols":
            return self._json({"symbols": sess.symbols()[:20000]})
        if route == "/api/re/functions":
            return self._json({"functions": sess.functions})
        if route == "/api/re/imports":
            return self._json({"imports": sess.imports()})
        if route == "/api/re/exports":
            return self._json({"exports": sess.exports()})
        if route == "/api/re/strings":
            return self._json({"strings": sess.strings()})
        if route == "/api/re/disasm":
            return self._json(sess.disasm_func(_addr()))
        if route == "/api/re/decompile":
            return self._json(sess.decompile(_addr()))
        if route == "/api/re/ai_decompile":
            from argus.re import ai as _reai
            return self._json(_reai.ai_decompile(sess, _addr()))
        if route == "/api/re/cfg":
            return self._json(sess.cfg(_addr()))
        if route == "/api/re/xrefs":
            return self._json({"addr": _addr(), "xrefs": sess.xrefs_to(_addr())})
        if route == "/api/re/hex":
            try:
                off = int(qs.get("off", ["0"])[0], 0)
                length = int(qs.get("len", ["512"])[0])
            except ValueError:
                off, length = 0, 512
            return self._json(sess.hexdump(off, length))
        if route == "/api/re/search":
            return self._json({"hits": sess.search(qs.get("q", [""])[0])})
        return self._json({"error": f"no route {route}"}, 404)

    def _re_post(self, route: str, payload: dict):
        from argus import re as remod
        if route == "/api/re/load":
            path = (payload.get("path") or "").strip()
            b64 = payload.get("b64")
            name = payload.get("name") or ""
            if b64:
                import base64
                try:
                    data = base64.b64decode(b64)
                except Exception:
                    return self._json({"error": "bad base64"}, 400)
                return self._json(remod.load_binary(name, data=data))
            if path:
                return self._json(remod.load_binary(name, path=path))
            return self._json({"error": "provide 'path' or 'b64'"}, 400)
        if route == "/api/re/asm":
            from argus.re import disasm as D
            return self._json(D.assemble(
                payload.get("code", ""), payload.get("arch", "x64"),
                int(payload.get("bits", 64)), int(payload.get("addr", 0))))
        if route == "/api/re/ask":
            from argus import re as remod
            sess = remod.get_session(payload.get("id", ""))
            if sess is None:
                return self._json({"error": "no such session — load a binary first"}, 404)
            from argus.re import ai as _reai
            try:
                addr = int(payload.get("addr", 0) or 0)
            except (ValueError, TypeError):
                addr = 0
            return self._json(_reai.ai_ask(sess, addr, payload.get("question", "")))
        return self._json({"error": "no route"}, 404)

    # --- endpoints ---------------------------------------------------------
    def _stats(self):
        idx = get_index()
        st = backend_status()
        self._json({
            "corpus_chunks": len(idx),
            "benchmark_items": _benchmark_count(),
            "provider": st["provider"],
            "model": st["model"],
            "max_steps": config.MAX_STEPS,
            "tools": [
                "retrieve_knowledge", "run_recon", "read_file", "list_dir", "grep",
                "record_candidate", "http_request", "kernel_research", "network_recon",
                "llm_redteam", "yara_scan", "unpack_sample", "triage_report",
            ],
            "vault": str(config.VAULT_ROOT),
            "api_ready": st["ready"],
            "api_error": st["error"],
        })

    def _progression(self):
        try:
            from argus import progression
            self._json(progression.snapshot())
        except Exception as e:
            self._json({"error": f"{type(e).__name__}: {e}"}, 500)

    def _workflow_status(self):
        try:
            from argus.workflow import workflow_status
            self._json(workflow_status())
        except Exception as e:
            self._json({"error": f"{type(e).__name__}: {e}"}, 500)

    def _devroom(self):
        try:
            from argus.devroom import read_messages
            msgs, _ = read_messages()
            self._json({"messages": msgs})
        except Exception as e:
            self._json({"error": f"{type(e).__name__}: {e}"}, 500)

    def _pipeline(self):
        """Aggregate command-center status for the whole collection→publish pipeline."""
        out = {"ok": True, "errors": {}}

        # Intake: samples in the queue
        try:
            qdir = config.INTAKE_DIR
            if qdir.exists():
                out["intake"] = {
                    "dir": str(qdir),
                    "samples": [f.name for f in qdir.iterdir() if f.is_file() and f.suffix.lower() == ".zip"],
                }
            else:
                out["intake"] = {"dir": str(qdir), "samples": []}
        except Exception as e:
            out["intake"] = {"samples": []}
            out["errors"]["intake"] = str(e)

        # Host-visible pipeline. Detonation runs in the GUEST, which keeps its own
        # seen-ledger the host never sees; the only artifacts that reach the host
        # are the DRAFTS copied into the review queue. So derive findings/verdicts/
        # published from the drafts — that's what actually moves during a VM hunt
        # (the host seen-ledger stays empty unless you detonate ON the host).
        try:
            from argus import autohunt, publish as _pub
            drafts = _pub.list_drafts()
            verdicts, published = {}, 0
            for x in drafts:
                v = x.get("verdict") or "unknown"
                verdicts[v] = verdicts.get(v, 0) + 1
                if str(x.get("status") or "").startswith("publish"):
                    published += 1
            try:
                host_seen = len(autohunt._load_seen())   # non-zero only for host-side detonation
            except Exception:
                host_seen = 0
            pending = autohunt.pending_reviews()
            out["detonation"] = {
                "seen_total": max(len(drafts), host_seen),  # host-visible findings
                "verdicts": verdicts,
                "published": published,
            }
            out["reviews"] = {
                "pending": len(pending),
                "items": [{"dir": p["dir"], "status": p["status"], "tweet": p["tweet"][:120]} for p in pending[:50]],
            }
        except Exception as e:
            out["detonation"] = {"seen_total": 0, "verdicts": {}, "published": 0}
            out["reviews"] = {"pending": 0, "items": []}
            out["errors"]["detonation"] = str(e)

        # Publish + autopilot
        try:
            from argus import autopublish, publish
            out["autopilot"] = autopublish.status()
            try:
                out["publish_batch"] = publish.batch_status()
            except Exception:
                out["publish_batch"] = {}
        except Exception as e:
            out["autopilot"] = {"running": False}
            out["errors"]["autopilot"] = str(e)

        # Jobs
        try:
            from argus import jobs
            out["jobs"] = {
                "types": jobs.job_types(),
                "active": [j for j in jobs.list_jobs() if j.get("status") in ("queued", "running")],
                "recent": jobs.list_jobs(limit=10),
            }
        except Exception as e:
            out["jobs"] = {"types": [], "active": [], "recent": []}
            out["errors"]["jobs"] = str(e)

        self._json(out)

    def _retrieve(self, payload):
        q = (payload.get("query") or "").strip()
        k = int(payload.get("k", 5))
        if not q:
            return self._json({"error": "query required"}, 400)
        hits = get_index().query(q, k=max(1, min(k, 10)))
        self._json({"query": q, "hits": hits})

    def _upload(self, payload):
        """Store a base64-encoded sample into the quarantine dir (never executed)."""
        import base64
        name = (payload.get("filename") or "sample.bin").strip()
        name = Path(name).name  # strip any path components
        data_b64 = payload.get("data_b64") or ""
        try:
            data = base64.b64decode(data_b64, validate=True)
        except Exception:
            return self._json({"error": "bad base64"}, 400)
        if not data:
            return self._json({"error": "empty file"}, 400)
        if len(data) > config.MAX_UPLOAD_BYTES:
            return self._json({"error": f"file exceeds {config.MAX_UPLOAD_BYTES} bytes"}, 413)
        import hashlib
        config.QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        sha = hashlib.sha256(data).hexdigest()
        dest = config.QUARANTINE_DIR / f"{sha[:16]}_{name}"
        dest.write_bytes(data)   # written, NOT executed
        self._json({"path": str(dest), "sha256": sha, "size": len(data), "filename": name})

    def _static_analyze(self, payload):
        """Analyze uploaded bytes locally and perform optional hash-only lookup."""
        import base64
        import hashlib
        from argus.tools.malware import analyze_file, lookup_virustotal_hash

        name = Path((payload.get("filename") or "sample.bin").strip()).name
        try:
            data = base64.b64decode(payload.get("data_b64") or "", validate=True)
        except Exception:
            return self._json({"error": "bad base64"}, 400)
        if not data:
            return self._json({"error": "empty file"}, 400)
        if len(data) > config.MAX_UPLOAD_BYTES:
            return self._json({"error": f"file exceeds {config.MAX_UPLOAD_BYTES} bytes"}, 413)

        # This is a quarantine write for repeatable parsing, never an execution path.
        config.QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        sha = hashlib.sha256(data).hexdigest()
        dest = config.QUARANTINE_DIR / f"{sha[:16]}_{name}"
        dest.write_bytes(data)
        analysis = analyze_file(dest)
        analysis["external"] = {
            "virustotal": lookup_virustotal_hash(sha),
            "malwarebazaar": f"https://bazaar.abuse.ch/sample/{sha}/",
        }
        analysis["safety"] = {
            "executed": False,
            "uploaded_to_public_services": False,
            "note": "Local byte parsing only; VirusTotal was queried by hash, not sample upload.",
        }
        self._json(analysis)

    def _runs(self):
        d = config.RUNS_DIR
        items = []
        if d.exists():
            for p in sorted(d.glob("hunt-*.json"), reverse=True)[:50]:
                try:
                    data = json.loads(p.read_text(encoding="utf-8"))
                    items.append({
                        "name": p.name,
                        "task": data.get("task", "")[:120],
                        "steps": data.get("steps"),
                        "stopped_reason": data.get("stopped_reason"),
                    })
                except Exception:
                    continue
        self._json({"runs": items})

    def _run_detail(self, name):
        if not name or "/" in name or "\\" in name:
            return self._json({"error": "bad name"}, 400)
        p = config.RUNS_DIR / name
        if not p.exists():
            return self._json({"error": "not found"}, 404)
        self._json(json.loads(p.read_text(encoding="utf-8")))

    def _sse_hunt(self, qs):
        task = (qs.get("task", [""])[0] or "").strip()
        mode = qs.get("mode", ["hunt"])[0]
        try:
            max_steps = int(qs.get("max_steps", ["0"])[0]) or None
        except ValueError:
            max_steps = None
        if not task:
            return self._json({"error": "task required"}, 400)

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        def emit(ev: dict):
            try:
                self.wfile.write(f"data: {json.dumps(ev)}\n\n".encode("utf-8"))
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                raise

        agent_mode = "triage" if mode == "triage" else "hunt"
        emit({"type": "open", "mode": mode, "task": task})
        agent, err = get_agent(agent_mode)
        if err is not None:
            emit({"type": "error", "message": err})
            emit({"type": "closed"})
            return

        if mode == "hunt":
            prompt = (
                f"Begin a vulnerability-research hunt on the following target/task:\n\n{task}\n\n"
                "Follow the operating procedure: orient via retrieve_knowledge, recon the "
                "attack surface, log hypotheses with record_candidate, and verify against the "
                "four gates. End with a prioritized candidate list and the single next experiment."
            )
            steps = max_steps or config.MAX_STEPS
        elif mode == "triage":
            prompt = (
                f"A suspicious sample is at: {task}\n\n"
                "Perform STATIC malware triage. If it is an archive, call unpack_sample first, "
                "then triage_report on the extracted files (or the quarantine dir). Produce an "
                "analyst triage summary: identification, verdict + confidence, capability "
                "hypotheses, and a deduplicated IOC table. Never execute the sample."
            )
            steps = max_steps or 20
        else:
            prompt = task
            steps = max_steps or 12

        try:
            result = agent.run(prompt, max_steps=steps, on_event=emit)
            try:
                agent.save_run(prompt, result)
            except Exception:
                pass
        except (BrokenPipeError, ConnectionResetError):
            return  # client navigated away
        except Exception as e:
            try:
                emit({"type": "error", "message": f"{type(e).__name__}: {e}"})
            except Exception:
                return
        try:
            emit({"type": "closed"})
        except Exception:
            pass

    # --- collaboration endpoints --------------------------------------------

    def _collab_sessions(self):
        d = COLLAB_SESSION_DIR if "COLLAB_SESSION_DIR" in dir() else config.RUNS_DIR / "collab"
        items = []
        if d.exists():
            for p in sorted(d.glob("collab-*.json"), reverse=True)[:30]:
                try:
                    data = json.loads(p.read_text(encoding="utf-8"))
                    items.append({
                        "name": p.name,
                        "task": data.get("task", "")[:100],
                        "agent_a": data.get("agent_a", ""),
                        "agent_b": data.get("agent_b", ""),
                        "turns": data.get("turns"),
                        "consensus": data.get("consensus", "")[:200],
                    })
                except Exception:
                    continue
        self._json({"sessions": items})

    def _collab_session(self, name):
        if not name or "/" in name or "\\" in name:
            return self._json({"error": "bad name"}, 400)
        d = config.RUNS_DIR / "collab"
        p = d / name
        if not p.exists():
            return self._json({"error": "not found"}, 404)
        self._json(json.loads(p.read_text(encoding="utf-8")))

    def _collab_stop(self):
        global _active_collab
        _active_collab = None
        self._json({"stopped": True})

    @staticmethod
    def _collab_llm_cfg(provider: str, model: str) -> dict:
        """Build a complete backend config for a collab seat.

        Collab seats may use different models through the same gateway key.
        AgentRouter and OpenRouter both expose an OpenAI-compatible endpoint,
        so the same key works for both.
        """
        provider = (provider or "agentrouter").strip().lower()
        model = (model or "").strip()
        if provider == "agentrouter":
            return {
                "provider": provider,
                "kind": "openai",
                "model": model or "z-ai/glm-5.2",
                "base_url": "https://agentrouter.org/v1",
                "api_key": os.environ.get("AGENTROUTER_API_KEY", ""),
            }
        if provider == "openrouter":
            return {
                "provider": provider,
                "kind": "openai",
                "model": model or "deepseek/deepseek-v4-pro",
                "base_url": "https://openrouter.ai/api/v1",
                "api_key": os.environ.get("OPENROUTER_API_KEY", ""),
            }
        if provider == "glm":
            return {
                "provider": provider,
                "kind": "openai",
                "model": model or "glm-5.2",
                "base_url": "https://open.bigmodel.cn/api/paas/v4",
                "api_key": os.environ.get("GLM_API_KEY", os.environ.get("ZHIPU_API_KEY", "")),
            }
        if provider == "deepseek":
            return {
                "provider": provider,
                "kind": "openai",
                "model": model or "deepseek-v4-pro",
                "base_url": "https://api.deepseek.com/v1",
                "api_key": os.environ.get("DEEPSEEK_API_KEY", ""),
            }
        if provider == "openai":
            return {
                "provider": provider,
                "kind": "openai",
                "model": model or "gpt-4o",
                "base_url": "https://api.openai.com/v1",
                "api_key": os.environ.get("OPENAI_API_KEY", ""),
            }
        if provider == "custom":
            return {
                "provider": provider,
                "kind": "openai",
                "model": model or "local-model",
                "base_url": os.environ.get("ARGUS_BASE_URL", "").strip(),
                "api_key": os.environ.get("ARGUS_API_KEY", ""),
            }
        if provider == "anthropic":
            return {
                "provider": provider,
                "kind": "anthropic",
                "model": model or "claude-sonnet-5",
                "base_url": "",
                "api_key": os.environ.get("ANTHROPIC_API_KEY", ""),
            }
        raise ValueError(f"unsupported collaboration provider: {provider}")

    def _collab_message(self, payload):
        global _active_collab, _collab_user_queue
        msg = (payload.get("message") or "").strip()
        if not msg:
            return self._json({"error": "message required"}, 400)
        if _active_collab is None:
            return self._json({"error": "no active collaboration"}, 400)
        _collab_user_queue.append(msg)
        self._json({"queued": True, "message": msg})

    def _sse_collab_start(self, payload):
        global _active_collab, _collab_user_queue
        task = (payload.get("task") or "").strip()
        if not task:
            return self._json({"error": "task required"}, 400)

        agent_a_provider = payload.get("agent_a_provider", "").strip() or "agentrouter"
        agent_a_model = payload.get("agent_a_model", "").strip() or "z-ai/glm-5.2"
        agent_b_provider = payload.get("agent_b_provider", "").strip() or "agentrouter"
        agent_b_model = payload.get("agent_b_model", "").strip() or "z-ai/glm-5.1"
        max_rounds = max(1, min(int(payload.get("max_rounds", 4)), 10))

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        def emit(ev: dict):
            try:
                self.wfile.write(f"data: {json.dumps(ev)}\n\n".encode("utf-8"))
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                raise

        try:
            from argus.collab import Collaboration

            collab = Collaboration(
                agent_a_cfg=self._collab_llm_cfg(agent_a_provider, agent_a_model),
                agent_b_cfg=self._collab_llm_cfg(agent_b_provider, agent_b_model),
                name_a=f"{agent_a_provider.title()} / {agent_a_model} (Primary)",
                name_b=f"{agent_b_provider.title()} / {agent_b_model} (Critic)",
            )

            _active_collab = collab
            _collab_user_queue = []
            collab._on_event = emit
            emit({
                "type": "collab_start",
                "task": task,
                "agent_a": collab.name_a,
                "agent_b": collab.name_b,
                "model_a": collab.backend_a.model,
                "model_b": collab.backend_b.model,
            })

            # Run collab in a thread, paying attention to user messages
            import threading as _thr
            result_holder = {"done": False}

            def _run():
                try:
                    for round_num in range(1, max_rounds * 2 + 1):
                        # Check for user-injected messages
                        while _collab_user_queue:
                            msg = _collab_user_queue.pop(0)
                            collab.inject_user_message(msg)

                        if round_num % 2 == 1:
                            collab._round = round_num
                            collab._run_primary_turn()
                        else:
                            collab._round = round_num
                            collab._run_critic_turn()

                        if collab._consensus:
                            break

                    if not collab._consensus:
                        collab._consensus = collab._final_synthesis()

                    emit({"type": "collab_end", "consensus": collab._consensus,
                          "turns": len(collab.turns)})
                    collab._save_session()
                except Exception as e:
                    try:
                        emit({"type": "error", "message": f"{type(e).__name__}: {e}"})
                    except Exception:
                        pass
                finally:
                    global _active_collab
                    _active_collab = None
                    result_holder["done"] = True

            _thr.Thread(target=_run, daemon=True, name="argus-collab").start()

            # Keep connection open
            import time
            while _active_collab is not None and not result_holder.get("done", False):
                time.sleep(0.5)

        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception as e:
            try:
                emit({"type": "error", "message": f"{type(e).__name__}: {e}"})
            except Exception:
                pass


_LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", ""}


def _guard_binding(host: str) -> None:
    """Fail closed: never expose the agent (which runs commands) on a network
    address without a token. Localhost stays open for single-user dev use."""
    if host not in _LOCAL_HOSTS and not config.WEB_TOKEN:
        raise SystemExit(
            f"REFUSING to bind to {host!r} without ARGUS_WEB_TOKEN set.\n"
            "The web agent can run shell commands and detonate samples, so an\n"
            "unauthenticated network endpoint is a remote-code-execution service.\n"
            "Fix: set ARGUS_WEB_TOKEN=<a long secret>, or bind to 127.0.0.1 and\n"
            "reach it over an SSH tunnel / Tailscale.")


def serve(host: str = "127.0.0.1", port: int = 8765):
    _load_dotenv()
    _guard_binding(host)
    from argus import jobs
    jobs.load_all()  # restore persisted research jobs (survive restarts)
    get_index()  # warm the corpus so first request is fast
    try:
        from argus import autopublish
        autopublish.maybe_autostart()  # opt-in via ARGUS_AUTOPUBLISH=1
    except Exception as e:
        print(f"  (autopublish not started: {e})")
    httpd = ThreadingHTTPServer((host, port), Handler)
    auth = "TOKEN AUTH ON" if config.WEB_TOKEN else ("open (localhost only)" if host in _LOCAL_HOSTS else "OPEN — no token!")
    print(f"ARGUS console -> http://{host}:{port}  [{auth}]  (Ctrl+C to stop)")
    if config.WEB_TOKEN:
        print(f"  open with:  http://{host}:{port}/?token=<your ARGUS_WEB_TOKEN>")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down.")
        httpd.shutdown()


def create_server(host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    """Return a started-but-not-yet-serving HTTP server object.

    Caller is responsible for calling serve_forever() or server_close().
    Used by the desktop tray app for start/stop control.
    """
    _load_dotenv()
    _guard_binding(host)
    get_index()
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"ARGUS console -> http://{host}:{port}"
          + ("  [TOKEN AUTH ON]" if config.WEB_TOKEN else ""))
    return httpd


if __name__ == "__main__":
    serve()
