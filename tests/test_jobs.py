"""Tests for the background job manager."""
import time

import pytest

import config
import argus.jobs as jobs


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "STATE_DIR", tmp_path / "state")
    jobs._JOBS.clear()
    yield
    jobs._JOBS.clear()


def test_submit_runs_to_completion():
    jobs.register("echo", lambda p, emit: (emit("working"), {"echoed": p.get("x")})[1])
    r = jobs.submit("echo", {"x": 42})
    assert r["ok"]
    j = jobs.wait(r["id"])
    assert j["status"] == "done"
    assert j["result"] == {"echoed": 42}
    assert any(entry["line"] == "working" for entry in j["log"])


def test_unknown_type():
    assert "unknown job type" in jobs.submit("nope")["error"]


def test_error_is_captured_not_raised():
    def boom(p, emit):
        raise ValueError("kaboom")
    jobs.register("boom", boom)
    j = jobs.wait(jobs.submit("boom")["id"])
    assert j["status"] == "error" and "kaboom" in j["error"]


def test_persists_and_reloads():
    jobs.register("noop", lambda p, emit: {"ok": True})
    jid = jobs.submit("noop")["id"]
    jobs.wait(jid)
    assert (config.STATE_DIR / "jobs" / f"{jid}.json").exists()
    # simulate a server restart
    jobs._JOBS.clear()
    assert jobs.get(jid) is None
    n = jobs.load_all()
    assert n >= 1 and jobs.get(jid)["status"] == "done"


def test_interrupted_marking(tmp_path):
    # a persisted job stuck in 'running' becomes 'interrupted' on reload
    jobs._jobs_dir()
    (config.STATE_DIR / "jobs" / "abc123.json").write_text(
        '{"id":"abc123","type":"x","status":"running","created":"t","updated":"t","log":[]}',
        encoding="utf-8")
    jobs.load_all()
    assert jobs.get("abc123")["status"] == "interrupted"


def test_list_and_types():
    jobs.register("noop", lambda p, emit: {})
    jobs.submit("noop")
    jobs.submit("noop")
    time.sleep(0.2)
    assert len(jobs.list_jobs()) >= 2
    assert {"hunt", "retrieve", "ioc", "sigma", "enrich"}.issubset(set(jobs.job_types()))
