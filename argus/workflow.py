"""Multi-agent autonomous workflow engine.

Two agents (OpenCode / Opus 5) share a task queue in tasks.jsonl. Each agent
polls the queue, claims tasks it owns, executes them, writes findings, and
handoffs to the other agent when collaboration is needed. The web panel shows
the live workflow state.

Protocol:
  pending  → agent claims → executing → handoff_to=other → pending (other picks up)
  pending  → agent claims → executing → done (no handoff needed)
  pending  → agent claims → executing → blocked (needs Muhammed)

Run:
  python run.py workflow --agent opencode --loop    # OpenCode session
  python run.py workflow --agent opus5 --loop       # Claude Opus 5 session
  python run.py workflow --once                     # single pass
"""
from __future__ import annotations

import json
import os
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import config

TASKS_FILE = config.ROOT / "tasks.jsonl"
WORKFLOW_DIR = config.ROOT / "runs" / "workflow"
WORKFLOW_DIR.mkdir(parents=True, exist_ok=True)

# Ownership map — which agent owns which domain.
# "both" means the task needs both agents.
DOMAINS = {
    "opencode": {"collab", "kernel", "http_request", "network_recon", "yara",
                 "hunt", "bug_bounty", "tools/http", "tools/network"},
    "opus5":    {"progression", "desktop", "profiles", "eval", "benchmark",
                 "triage_ui", "build", "panel"},
    "both":     {"shared_files", "review", "debate", "consensus", "integration",
                 "config", "run_py", "server_py", "index_html"},
}

PHASES = {"hunt", "review", "build", "fix", "debate", "verify", "integrate"}

DEFAULT_POLL_SECONDS = 10
MAX_HUNT_STEPS = 30

VALID_STATUSES = {"pending", "claimed", "executing", "handoff", "done", "blocked", "dead"}

_TS = lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")


def resolve_owner(task_domain: str) -> str:
    """Which agent owns this domain? Returns 'opencode', 'opus5', or 'both'."""
    domain = task_domain.lower().strip()
    for owner, domains in DOMAINS.items():
        for d in domains:
            if d in domain:
                return owner
    return "both"  # default to collaboration


@dataclass
class Task:
    id: str
    title: str
    domain: str = ""
    phase: str = "hunt"
    owner: str = ""        # opencode / opus5 / both
    status: str = "pending"
    priority: str = "medium"
    created_by: str = "muhammed"
    created_at: str = ""
    claimed_by: str = ""
    claimed_at: str = ""
    completed_at: str = ""
    handoff_to: str = ""
    handoff_msg: str = ""
    max_hunt_steps: int = 0
    artifacts: list[str] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    history: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "title": self.title, "domain": self.domain,
            "phase": self.phase, "owner": self.owner, "status": self.status,
            "priority": self.priority, "created_by": self.created_by,
            "created_at": self.created_at, "claimed_by": self.claimed_by,
            "claimed_at": self.claimed_at, "completed_at": self.completed_at,
            "handoff_to": self.handoff_to, "handoff_msg": self.handoff_msg,
            "max_hunt_steps": self.max_hunt_steps,
            "artifacts": self.artifacts, "findings": self.findings,
            "history": self.history,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Task":
        return cls(
            id=d.get("id", ""), title=d.get("title", ""), domain=d.get("domain", ""),
            phase=d.get("phase", "hunt"), owner=d.get("owner", ""),
            status=d.get("status", "pending"), priority=d.get("priority", "medium"),
            created_by=d.get("created_by", "muhammed"), created_at=d.get("created_at", ""),
            claimed_by=d.get("claimed_by", ""), claimed_at=d.get("claimed_at", ""),
            completed_at=d.get("completed_at", ""),
            handoff_to=d.get("handoff_to", ""), handoff_msg=d.get("handoff_msg", ""),
            max_hunt_steps=d.get("max_hunt_steps", 0),
            artifacts=d.get("artifacts", []), findings=d.get("findings", []),
            history=d.get("history", []),
        )


# ---------------------------------------------------------------------------
# queue I/O
# ---------------------------------------------------------------------------
def load_tasks() -> list[dict]:
    if not TASKS_FILE.exists():
        return []
    tasks = []
    with TASKS_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    tasks.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return tasks


def save_tasks(tasks: list[dict]) -> None:
    TASKS_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = TASKS_FILE.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        for t in tasks:
            f.write(json.dumps(t, ensure_ascii=False) + "\n")
    os.replace(tmp, TASKS_FILE)


def update_task(task_dict: dict) -> None:
    """Atomically update one task in the queue. Must include the original index."""
    tasks = load_tasks()
    for i, t in enumerate(tasks):
        if t.get("id") == task_dict["id"]:
            tasks[i] = task_dict
            break
    else:
        tasks.append(task_dict)
    save_tasks(tasks)


def seed_tasks() -> int:
    """Write initial task examples if tasks.jsonl is empty."""
    if TASKS_FILE.exists() and TASKS_FILE.stat().st_size > 0:
        return 0

    tasks = [
        Task(
            id="task-001", title="Audit USBPcap.sys IOCTL surface for kernel LPE",
            domain="kernel", phase="hunt", owner="opencode", priority="critical",
            created_at=_TS(),
            max_hunt_steps=30,
        ),
        Task(
            id="task-002", title="Verify Vendor Updater named-pipe DACL — standard user reachable?",
            domain="hunt", phase="hunt", owner="opencode", priority="high",
            created_at=_TS(),
            max_hunt_steps=25,
        ),
        Task(
            id="task-003", title="Build the progression-to-PANEL leaderboard integration",
            domain="panel", phase="build", owner="opus5", priority="medium",
            created_at=_TS(),
        ),
        Task(
            id="task-004", title="Run eval/benchmark and improve exemplars from new findings",
            domain="eval", phase="verify", owner="opus5", priority="medium",
            created_at=_TS(),
        ),
        Task(
            id="task-005", title="Integration test: collab debate + progression XP wiring",
            domain="integration", phase="integrate", owner="both", priority="high",
            created_at=_TS(),
        ),
    ]
    save_tasks([t.to_dict() for t in tasks])
    return len(tasks)


# ---------------------------------------------------------------------------
# agent: wraps the LLM backend with agent identity
# ---------------------------------------------------------------------------
class WorkflowAgent:
    """An autonomous agent in the workflow. Wraps an ARGUS backend + tools."""

    def __init__(self, name: str):
        self.name = name  # "opencode" or "opus5"
        self._backend = None
        self._tools = None
        self._dispatch = None
        self._index = None
        self._system = None
        self.on_event: Callable | None = None

    def _init_backend(self):
        if self._backend is not None:
            return
        from .llm import make_backend
        from .prompts import build_system_prompt
        from .rag import BM25Index
        from .tools import build_tools

        self._backend = make_backend()
        self._index = BM25Index.from_corpus(config.CORPUS_FILE)
        self._tools, self._dispatch = build_tools(self._index)
        self._system = build_system_prompt(mode="hunt")

    @property
    def model(self) -> str:
        self._init_backend()
        return self._backend.model

    @property
    def ready(self) -> bool:
        self._init_backend()
        return self._backend.ready

    def _emit(self, kind: str, **data) -> None:
        if self.on_event:
            try:
                self.on_event({"type": kind, agent: self.name, **data})
            except Exception:
                pass

    def execute_hunt(self, task: Task) -> Task:
        """Run a full VR hunt for the given task. Returns updated task."""
        self._init_backend()
        task.status = "executing"
        task.claimed_by = self.name
        task.claimed_at = _TS()
        task.history.append({"ts": _TS(), "agent": self.name, "action": "claimed",
                             "phase": task.phase})

        from .llm import BackendError

        # Build the hunt prompt
        domain_hints = {
            "kernel": "Focus on kernel driver IOCTL surface, buffer validation, access checks.",
            "hunt": "Standard VR hunt: enumerate attack surface, find bugs, verify gates.",
            "collab": "Review collaboration code for bugs, integration gaps, edge cases.",
            "bug_bounty": "Web bug bounty: test APIs for SSRF, IDOR, SQLi, XSS, auth bypass.",
            "review": "Review the previous agent's findings. Challenge assumptions. Demand evidence.",
            "build": "Implement the feature. Write code, run tests, verify.",
            "fix": "Fix the reported bug. Write minimal changes, verify the fix.",
            "verify": "Verify previous findings. Reproduce, confirm, or debunk.",
            "integrate": "Ensure all components work together. Run integration tests.",
        }
        hint = domain_hints.get(task.domain, domain_hints["hunt"])

        prompt = (
            f"# WORKFLOW TASK — {self.name.upper()}\n\n"
            f"Task: {task.title}\n"
            f"Domain: {task.domain}\n"
            f"Priority: {task.priority}\n\n"
            f"{hint}\n\n"
        )

        # Include handoff context
        if task.handoff_msg:
            prompt += f"## Handoff from previous agent\n{task.handoff_msg}\n\n"

        # Include previous findings
        for i, f in enumerate(task.findings):
            prompt += f"### Previous finding {i+1}: {f.get('title', '?')}\n{f.get('text', f.get('hypothesis', ''))[:500]}\n\n"

        prompt += (
            "Execute your phase. Use tools as needed. If you reach a conclusion, "
            "state it clearly. If you need the other agent's input, explain what "
            "you need them to verify or review."
        )

        max_steps = task.max_hunt_steps or MAX_HUNT_STEPS
        history: list[dict] = [{"role": "user", "text": prompt}]
        final_text = ""
        stopped = "completed"

        for step in range(1, max_steps + 1):
            self._emit("workflow_step", task_id=task.id, step=step, max_steps=max_steps)
            try:
                resp = self._backend.converse(self._system, history, self._tools)
            except BackendError as e:
                task.history.append({"ts": _TS(), "agent": self.name,
                                     "action": "error", "error": str(e)})
                task.status = "blocked"
                task.handoff_msg = f"ERROR: {e}"
                return task

            history.append({"role": "assistant", "text": resp.get("text", ""),
                           "tool_calls": resp.get("tool_calls", [])})
            if resp.get("text"):
                final_text = resp["text"]

            if resp.get("stop") or not resp.get("tool_calls"):
                break

            results = []
            for tc in resp.get("tool_calls", []):
                handler = self._dispatch.get(tc["name"])
                if handler is None:
                    out = f"ERROR: unknown tool {tc['name']}"
                else:
                    try:
                        out = handler(tc["input"])
                    except Exception as e:
                        out = f"ERROR: {type(e).__name__}: {e}"
                results.append({"id": tc.get("id", ""), "name": tc["name"], "output": out})
                self._emit("workflow_tool", task_id=task.id, name=tc["name"],
                           input=tc["input"], output=out[:500])
            history.append({"role": "tool", "results": results})
        else:
            stopped = "max_steps"

        # Determine next action
        task.findings.append({
            "agent": self.name, "title": task.title,
            "text": final_text[:2000], "stopped": stopped,
            "step_count": step,
        })
        task.history.append({"ts": _TS(), "agent": self.name, "action": "completed",
                             "stopped": stopped, "steps": step})

        # Smart handoff: detect if the agent is asking the other for review
        needs_handoff = any(phrase in final_text.lower() for phrase in [
            "needs review", "needs opus", "needs opencode", "needs claude",
            "please verify", "please review", "handoff", "second opinion",
            "other agent should", "needs both", "@opus", "@opencode",
        ])

        if needs_handoff:
            task.status = "handoff"
            task.handoff_to = "opus5" if self.name == "opencode" else "opencode"
            task.handoff_msg = (
                f"[{self.name}] completed hunting phase on '{task.title}'. "
                f"Please review these findings and challenge or confirm:\n\n"
                f"{final_text[:1500]}"
            )
        else:
            task.status = "done"
            task.completed_at = _TS()

        # Save this run
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        run_path = WORKFLOW_DIR / f"{self.name}-{task.id}-{stamp}.json"
        run_path.write_text(json.dumps({
            "task": task.to_dict(), "prompt": prompt,
            "final_text": final_text, "steps": step, "stopped": stopped,
        }, indent=2), encoding="utf-8")
        task.artifacts.append(str(run_path))

        return task

    def execute_review(self, task: Task) -> Task:
        """Review another agent's findings. Returns updated task."""
        self._init_backend()

        task.status = "executing"
        task.claimed_by = self.name
        task.claimed_at = _TS()

        # Collect the previous agent's findings
        review_targets = "\n\n".join(
            f"### Finding from {f.get('agent', '?')}: {f.get('title', '?')}\n{f.get('text', '')[:1500]}"
            for f in task.findings[-3:]  # last 3 findings
        )

        prompt = (
            f"# WORKFLOW REVIEW — {self.name.upper()}\n\n"
            f"Task: {task.title}\n"
            f"Previous agent's findings:\n\n{review_targets}\n\n"
            "You are the REVIEWER. Critically examine these findings:\n"
            "1. Are claims correct? Challenge each one.\n"
            "2. Is evidence sufficient? Demand more if not.\n"
            "3. What's missing? What should have been checked but wasn't?\n"
            "4. Rate each finding: CONFIRMED / NEEDS MORE WORK / DEBUNKED.\n"
            "5. If confirmed, state the evidence that convinced you.\n"
            "6. If debunked, explain exactly why.\n"
        )

        history: list[dict] = [{"role": "user", "text": prompt}]
        final_text = ""

        for step in range(1, 8):
            try:
                resp = self._backend.converse(self._system, history, self._tools)
            except Exception as e:
                task.status = "blocked"
                return task
            history.append({"role": "assistant", "text": resp.get("text", ""),
                           "tool_calls": resp.get("tool_calls", [])})
            if resp.get("text"):
                final_text = resp["text"]
            if resp.get("stop") or not resp.get("tool_calls"):
                break
            results = []
            for tc in resp.get("tool_calls", []):
                handler = self._dispatch.get(tc["name"])
                out = handler(tc["input"]) if handler else "ERROR"
                results.append({"id": tc.get("id", ""), "name": tc["name"], "output": out})
            history.append({"role": "tool", "results": results})

        task.findings.append({
            "agent": self.name, "title": f"REVIEW: {task.title}",
            "text": final_text[:2000],
        })

        # If both agree → done. If disagree → handoff back.
        if "confirmed" in final_text.lower() and "debunked" not in final_text.lower():
            task.status = "done"
            task.completed_at = _TS()
        elif "debunked" in final_text.lower():
            task.status = "handoff"
            task.handoff_to = "opencode" if self.name == "opus5" else "opus5"
            task.handoff_msg = f"[{self.name}] review — {final_text[:1000]}"
        else:
            # Still uncertain — handoff back
            task.status = "handoff"
            task.handoff_to = "opencode" if self.name == "opus5" else "opus5"
            task.handoff_msg = f"[{self.name}] review — needs more evidence:\n{final_text[:1000]}"

        task.history.append({"ts": _TS(), "agent": self.name, "action": "reviewed"})
        return task


# ---------------------------------------------------------------------------
# orchestrator loop
# ---------------------------------------------------------------------------
class WorkflowEngine:
    """Polls tasks.jsonl, claims matching tasks, executes, handoffs."""

    def __init__(self, agent_name: str, on_event: Callable | None = None):
        self.agent_name = agent_name
        self.agent = WorkflowAgent(agent_name)
        self.agent.on_event = on_event
        self.running = False

    def poll_and_execute(self, once: bool = False) -> int:
        """Execute one pass over the task queue. Returns tasks completed."""
        tasks = load_tasks()
        if not tasks:
            return 0

        completed = 0
        for tdict in tasks:
            task = Task.from_dict(tdict)

            # Is this task for us?
            owner = task.owner or resolve_owner(task.domain)
            if owner != self.agent_name and owner != "both":
                continue

            # Can we act on it?
            if task.status == "done" or task.status == "dead" or task.status == "blocked":
                continue

            if task.status in ("pending", "handoff"):
                print(f"\n[{self.agent_name}] CLAIMED: {task.title} ({task.domain})")

                if task.phase == "review" or task.status == "handoff":
                    task = self.agent.execute_review(task)
                else:
                    task = self.agent.execute_hunt(task)

                update_task(task.to_dict())

                if task.status == "done":
                    print(f"[{self.agent_name}] DONE: {task.title}")
                    completed += 1
                elif task.status == "handoff":
                    print(f"[{self.agent_name}] HANDOFF → {task.handoff_to}: {task.title}")
                elif task.status == "blocked":
                    print(f"[{self.agent_name}] BLOCKED: {task.title} — needs Muhammed")

            elif task.status == "claimed":
                # Someone else claimed it — skip
                continue

        return completed

    def loop(self, interval: int = DEFAULT_POLL_SECONDS, once: bool = False):
        """Run the autonomous loop. Polls tasks.jsonl every `interval` seconds."""
        self.running = True
        print(f"[{self.agent_name}] Workflow agent started. Polling tasks.jsonl every {interval}s.")
        print(f"[{self.agent_name}] Model: {self.agent.model}  API: {'ready' if self.agent.ready else 'NOT READY'}")

        try:
            while self.running:
                completed = self.poll_and_execute()

                if completed:
                    print(f"[{self.agent_name}] Cycle done — {completed} task(s) completed.")
                elif once:
                    pending = sum(1 for t in load_tasks()
                                  if t["status"] not in ("done", "dead", "blocked")
                                  and t.get("owner", "") in (self.agent_name, "both"))
                    print(f"[{self.agent_name}] Cycle done — no actionable tasks. {pending} pending for me.")
                    break

                if once:
                    break

                time.sleep(interval)
        except KeyboardInterrupt:
            print(f"\n[{self.agent_name}] Stopped.")
            self.running = False

    def stop(self):
        self.running = False


def workflow_status() -> dict:
    """Readable summary for the web panel."""
    tasks = load_tasks()
    counts = Counter(t.get("status", "?") for t in tasks)
    return {
        "total": len(tasks),
        "pending": counts.get("pending", 0),
        "claimed": counts.get("claimed", 0),
        "executing": counts.get("executing", 0),
        "handoff": counts.get("handoff", 0),
        "done": counts.get("done", 0),
        "blocked": counts.get("blocked", 0),
        "by_owner": {
            "opencode": sum(1 for t in tasks if t.get("owner") in ("opencode", "both")),
            "opus5": sum(1 for t in tasks if t.get("owner") in ("opus5", "both")),
        },
        "tasks": tasks,
    }
