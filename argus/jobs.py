"""Background job manager — the 'research computer' core.

Submit any registered capability as a JOB: it runs server-side in a daemon
thread, accumulates a live log, PERSISTS to disk (survives closing the browser
tab or restarting the server), and its result is browsable later. This turns the
web console from 'watch one live stream' into 'a computer that holds your work'.

Jobs live under config.STATE_DIR/jobs/<id>.json. Handlers are registered by type;
each is `handler(params: dict, emit: callable) -> result`.
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from datetime import datetime, timezone

import config

_LOCK = threading.RLock()
_JOBS: dict[str, dict] = {}
_HANDLERS: dict[str, callable] = {}
_MAX_LOG = 3000


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _jobs_dir():
    d = config.STATE_DIR / "jobs"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _save(job: dict) -> None:
    p = _jobs_dir() / f"{job['id']}.json"
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(job, indent=2, default=str), encoding="utf-8")
    tmp.replace(p)


def register(job_type: str, handler) -> None:
    _HANDLERS[job_type] = handler


def job_types() -> list[str]:
    return sorted(_HANDLERS)


def submit(job_type: str, params: dict | None = None) -> dict:
    if job_type not in _HANDLERS:
        return {"error": f"unknown job type '{job_type}'. Known: {', '.join(job_types())}"}
    jid = uuid.uuid4().hex[:12]
    job = {"id": jid, "type": job_type, "params": params or {}, "status": "queued",
           "created": _now(), "updated": _now(), "log": [], "result": None, "error": None}
    with _LOCK:
        _JOBS[jid] = job
        _save(job)
    threading.Thread(target=_run, args=(jid,), daemon=True).start()
    return {"ok": True, "id": jid}


def _run(jid: str) -> None:
    with _LOCK:
        job = _JOBS[jid]
        job["status"] = "running"
        job["updated"] = _now()
        _save(job)
    handler = _HANDLERS[job["type"]]

    def emit(line) -> None:
        with _LOCK:
            job["log"].append({"ts": _now(), "line": str(line)})
            if len(job["log"]) > _MAX_LOG:
                job["log"] = job["log"][-_MAX_LOG:]
            job["updated"] = _now()
            _save(job)

    try:
        result = handler(job["params"], emit)
        with _LOCK:
            job["status"] = "done"
            job["result"] = result
            job["updated"] = _now()
            _save(job)
    except Exception as e:  # a failed job must not take the server down
        with _LOCK:
            job["status"] = "error"
            job["error"] = f"{type(e).__name__}: {e}"
            job["updated"] = _now()
            _save(job)


def get(jid: str) -> dict | None:
    with _LOCK:
        return json.loads(json.dumps(_JOBS[jid], default=str)) if jid in _JOBS else None


def list_jobs(limit: int = 100) -> list[dict]:
    with _LOCK:
        jobs = sorted(_JOBS.values(), key=lambda j: j["created"], reverse=True)
        return [{k: j.get(k) for k in ("id", "type", "status", "created", "updated")}
                for j in jobs[:limit]]


def wait(jid: str, timeout: float = 10.0) -> dict | None:
    """Block until a job finishes (for the CLI / tests). Returns the final job."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        j = get(jid)
        if j and j["status"] in ("done", "error", "interrupted"):
            return j
        time.sleep(0.05)
    return get(jid)


def load_all() -> int:
    """Load persisted jobs on startup; mark any that were mid-run as interrupted."""
    n = 0
    with _LOCK:
        for p in _jobs_dir().glob("*.json"):
            try:
                job = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            if job.get("status") == "running":
                job["status"] = "interrupted"
            _JOBS[job["id"]] = job
            n += 1
    return n


# ---------------------------------------------------------------------------
# default handlers — the capabilities you can submit as jobs
# ---------------------------------------------------------------------------
def _h_retrieve(params: dict, emit) -> dict:
    from .rag import BM25Index
    emit(f"RAG query: {params.get('query', '')!r}")
    idx = BM25Index.from_corpus(config.CORPUS_FILE)
    hits = idx.query(params.get("query", ""), k=int(params.get("k", 5)))
    return {"hits": [{"score": h["score"], "source": h.get("meta", {}).get("source"),
                      "text": h["text"][:500]} for h in hits]}


def _h_hunt(params: dict, emit) -> dict:
    from .agent import Argus
    agent = Argus(verbose=False, mode=params.get("mode", "hunt"))
    emit(f"starting {params.get('mode', 'hunt')}: {params.get('task', '')[:200]}")

    def on_event(ev):
        t = ev.get("type")
        if t == "text" and ev.get("text"):
            emit(ev["text"][:2000])
        elif t == "tool_call":
            emit(f"-> {ev.get('name')}({str(ev.get('input', ''))[:120]})")
        elif t == "tool_result":
            emit(f"<- {ev.get('name')}: {str(ev.get('output', ''))[:300]}")

    r = agent.run(params.get("task", ""), max_steps=int(params.get("max_steps", 12)),
                  on_event=on_event)
    return {"final_text": r.final_text, "steps": r.steps, "stopped_reason": r.stopped_reason}


def _h_ioc(params: dict, emit) -> dict:
    from .ioc import extract_run
    emit(f"extracting IOCs from {params.get('run', '')}")
    return extract_run(params.get("run", ""))


def _h_sigma(params: dict, emit) -> dict:
    from .sigma_gen import generate_run
    emit(f"generating Sigma rules from {params.get('run', '')}")
    return generate_run(params.get("run", ""))


def _h_enrich(params: dict, emit) -> dict:
    from .intel import virustotal
    from pathlib import Path
    if not virustotal.available():
        return {"error": "no VT_API_KEY set"}
    fj = Path(params.get("run", "")) / "findings.json"
    if not fj.exists():
        return {"error": f"no findings.json in {params.get('run', '')}"}
    struct = json.loads(fj.read_text(encoding="utf-8"))
    emit(f"VirusTotal lookup for {struct.get('sha256', '')[:16]}")
    virustotal.enrich(struct)
    fj.write_text(json.dumps(struct, indent=2), encoding="utf-8")
    return {"verdict": struct.get("verdict"), "vt": struct.get("vt"),
            "vt_conflict": struct.get("vt_conflict")}


def register_defaults() -> None:
    register("retrieve", _h_retrieve)
    register("hunt", _h_hunt)
    register("ask", _h_hunt)      # alias: a short agent task
    register("ioc", _h_ioc)
    register("sigma", _h_sigma)
    register("enrich", _h_enrich)


register_defaults()
