"""Provider-agnostic LLM backends for ARGUS.

Two backends behind one interface:
  - OpenAICompatBackend: pure-stdlib HTTP to any OpenAI-compatible
    /chat/completions endpoint — DeepSeek, OpenAI, or a local server
    (Ollama / LM Studio / vLLM). No third-party package required.
  - AnthropicBackend: the Anthropic Messages API via the `anthropic` SDK.

The agent speaks a provider-neutral message format and each backend translates
to/from its own wire format on every call (stateless translation), so the agent
loop stays identical across providers.

Neutral history entries (list of dict):
  {"role":"user","text": str}
  {"role":"assistant","text": str, "tool_calls":[{"id","name","input"}]}
  {"role":"tool","results":[{"id","name","output"}]}

Tool schema (neutral): {"name","description","input_schema"}  (JSON Schema).

converse(system, history, tools) -> {"text": str, "tool_calls":[{id,name,input}], "stop": bool}
"""
from __future__ import annotations

import json
import random
import time
import urllib.error
import urllib.request

import config


class BackendError(RuntimeError):
    pass


# Transient HTTP statuses worth retrying (rate limit / server / overloaded).
_RETRYABLE_STATUS = {429, 500, 502, 503, 504, 529}
# How many times a single model round-trip is retried before it gives up. A hunt
# can be 40 round-trips long, so one transient blip must not sink the whole run.
_MAX_RETRIES = int(getattr(config, "LLM_MAX_RETRIES", 4))


def _backoff_sleep(attempt: int, retry_after: float | None = None) -> None:
    """Exponential backoff with jitter, capped at 30s; honours Retry-After."""
    if retry_after is not None:
        time.sleep(min(retry_after, 60.0))
        return
    delay = min(2.0 ** attempt + random.uniform(0, 1), 30.0)
    time.sleep(delay)


# ---------------------------------------------------------------------------
# OpenAI-compatible (DeepSeek / OpenAI / local) — stdlib only
# ---------------------------------------------------------------------------
class OpenAICompatBackend:
    def __init__(self, cfg: dict):
        self.provider = cfg["provider"]
        self.kind = "openai"
        self.model = cfg["model"]
        self.base_url = cfg["base_url"].rstrip("/")
        self.api_key = cfg["api_key"]
        self._local = any(h in self.base_url for h in ("localhost", "127.0.0.1", "0.0.0.0"))
        self._is_openrouter = "openrouter.ai" in self.base_url

    @property
    def ready(self) -> bool:
        # A key is required for hosted providers; local servers usually don't need one.
        return bool(self.base_url) and (bool(self.api_key) or self._local)

    @property
    def error(self):
        if not self.base_url:
            return "no base_url configured"
        if not self.api_key and not self._local:
            return f"no API key for provider '{self.provider}' (set DEEPSEEK_API_KEY / ARGUS_API_KEY)"
        return None

    def _post(self, payload: dict) -> dict:
        url = f"{self.base_url}/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        if self._is_openrouter:
            headers["HTTP-Referer"] = "https://github.com/anomalyco/argus"
            headers["X-Title"] = "ARGUS VR Agent"
        data = json.dumps(payload).encode("utf-8")
        # Retry transient failures (rate limit / 5xx / network) with backoff, so
        # a single blip mid-hunt doesn't sink a 40-step run. 4xx (bad key, bad
        # balance, malformed request) fail fast — retrying can't help them.
        for attempt in range(_MAX_RETRIES + 1):
            req = urllib.request.Request(url, data=data, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=300) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as e:
                body = e.read().decode("utf-8", "ignore")
                if e.code in _RETRYABLE_STATUS and attempt < _MAX_RETRIES:
                    ra = e.headers.get("Retry-After") if e.headers else None
                    _backoff_sleep(attempt, float(ra) if ra and ra.isdigit() else None)
                    continue
                hint = {
                    401: " — bad/expired API key.",
                    402: " — insufficient balance; top up your account (DeepSeek is prepaid: platform.deepseek.com/top_up).",
                    429: " — rate-limited; slow down or check your quota.",
                }.get(e.code, "")
                raise BackendError(f"HTTP {e.code} from {self.provider}{hint} {body[:300]}")
            except urllib.error.URLError as e:
                if attempt < _MAX_RETRIES:
                    _backoff_sleep(attempt)
                    continue
                raise BackendError(f"cannot reach {url}: {e.reason}")
        raise BackendError(f"{self.provider}: exhausted {_MAX_RETRIES} retries")

    @staticmethod
    def _to_messages(system: str, history: list[dict]) -> list[dict]:
        msgs = [{"role": "system", "content": system}]
        for h in history:
            if h["role"] == "user":
                msgs.append({"role": "user", "content": h.get("text", "")})
            elif h["role"] == "assistant":
                m = {"role": "assistant", "content": h.get("text") or ""}
                tcs = h.get("tool_calls") or []
                if tcs:
                    m["tool_calls"] = [{
                        "id": tc["id"], "type": "function",
                        "function": {"name": tc["name"], "arguments": json.dumps(tc["input"])},
                    } for tc in tcs]
                msgs.append(m)
            elif h["role"] == "tool":
                for r in h.get("results", []):
                    msgs.append({"role": "tool", "tool_call_id": r["id"], "content": r["output"]})
        return msgs

    def _tools(self, tools: list[dict]) -> list[dict]:
        return [{"type": "function", "function": {
            "name": t["name"], "description": t["description"], "parameters": t["input_schema"],
        }} for t in tools]

    def converse(self, system: str, history: list[dict], tools: list[dict]) -> dict:
        payload = {
            "model": self.model,
            "messages": self._to_messages(system, history),
            "tools": self._tools(tools),
            "tool_choice": "auto",
            "max_tokens": config.MAX_TOKENS,
            "temperature": config.TEMPERATURE,
        }
        data = self._post(payload)
        try:
            msg = data["choices"][0]["message"]
        except (KeyError, IndexError):
            raise BackendError(f"unexpected response shape: {json.dumps(data)[:400]}")
        text = msg.get("content") or ""
        tool_calls = []
        for tc in msg.get("tool_calls") or []:
            fn = tc.get("function", {})
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            tool_calls.append({"id": tc.get("id", ""), "name": fn.get("name", ""), "input": args})
        return {"text": text, "tool_calls": tool_calls, "stop": not tool_calls}

    def complete(self, prompt: str) -> str:
        # Reasoning models (deepseek-reasoner / deepseek-v4-pro / etc.) spend the
        # token budget on hidden reasoning BEFORE writing `content`, so a small
        # max_tokens gets fully consumed by reasoning and returns empty content.
        # Give generous headroom. If the model still returns empty content but
        # produced reasoning, surface a hint rather than a silent blank.
        data = self._post({
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 2048, "temperature": 0,
        })
        try:
            msg = data["choices"][0]["message"]
        except (KeyError, IndexError):
            return ""
        content = (msg.get("content") or "").strip()
        if content:
            return content
        if (msg.get("reasoning_content") or "").strip():
            return "(model produced only reasoning, no answer — try raising max_tokens)"
        return ""


# ---------------------------------------------------------------------------
# Anthropic
# ---------------------------------------------------------------------------
class AnthropicBackend:
    def __init__(self, cfg: dict):
        self.provider = "anthropic"
        self.kind = "anthropic"
        self.model = cfg["model"]
        self.api_key = cfg["api_key"]
        self._client = None
        self._import_err = None
        try:
            import anthropic  # noqa: F401
        except Exception as e:
            self._import_err = f"{type(e).__name__}: {e} (pip install anthropic)"

    @property
    def ready(self) -> bool:
        return bool(self.api_key) and self._import_err is None

    @property
    def error(self):
        if self._import_err:
            return self._import_err
        if not self.api_key:
            return "no ANTHROPIC_API_KEY"
        return None

    def _get_client(self):
        if self._client is None:
            import anthropic
            # The SDK auto-retries 429/5xx/overloaded with backoff; lift the
            # default (2) so a long hunt survives a transient overload spike.
            self._client = anthropic.Anthropic(api_key=self.api_key, max_retries=_MAX_RETRIES)
        return self._client

    @staticmethod
    def _to_messages(history: list[dict], cache_last: bool = False) -> list[dict]:
        msgs = []
        for h in history:
            if h["role"] == "user":
                msgs.append({"role": "user", "content": [{"type": "text", "text": h.get("text", "")}]})
            elif h["role"] == "assistant":
                content = []
                if h.get("text"):
                    content.append({"type": "text", "text": h["text"]})
                for tc in h.get("tool_calls") or []:
                    content.append({"type": "tool_use", "id": tc["id"], "name": tc["name"], "input": tc["input"]})
                msgs.append({"role": "assistant", "content": content or [{"type": "text", "text": ""}]})
            elif h["role"] == "tool":
                content = [{"type": "tool_result", "tool_use_id": r["id"], "content": r["output"]}
                           for r in h.get("results", [])]
                msgs.append({"role": "user", "content": content})
        # Mark the final content block as a cache breakpoint so each step reuses
        # the entire prior-conversation prefix instead of re-billing it in full.
        if cache_last and msgs and msgs[-1]["content"]:
            msgs[-1]["content"][-1]["cache_control"] = {"type": "ephemeral"}
        return msgs

    def converse(self, system: str, history: list[dict], tools: list[dict]) -> dict:
        client = self._get_client()
        tool_defs = [{"name": t["name"], "description": t["description"], "input_schema": t["input_schema"]}
                     for t in tools]
        # Cache the static prefix. A breakpoint on the system block covers the
        # tool definitions too (render order is tools -> system), so the doctrine,
        # exemplars, and every tool schema are re-read from cache each step at ~0.1x
        # cost instead of full price. A second breakpoint on the last message caches
        # the growing hunt transcript incrementally.
        resp = client.messages.create(
            model=self.model, max_tokens=config.MAX_TOKENS,
            system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
            tools=tool_defs,
            messages=self._to_messages(history, cache_last=True),
        )
        text_bits, tool_calls = [], []
        for block in resp.content:
            if block.type == "text":
                text_bits.append(block.text)
            elif block.type == "tool_use":
                tool_calls.append({"id": block.id, "name": block.name, "input": block.input})
        return {"text": "\n".join(text_bits), "tool_calls": tool_calls,
                "stop": resp.stop_reason != "tool_use"}

    def complete(self, prompt: str) -> str:
        resp = self._get_client().messages.create(
            model=self.model, max_tokens=512,
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(b.text for b in resp.content if b.type == "text")


# ---------------------------------------------------------------------------
def make_backend(cfg: dict | None = None):
    cfg = cfg or config.resolve_llm()
    if cfg["kind"] == "anthropic":
        return AnthropicBackend(cfg)
    return OpenAICompatBackend(cfg)


def backend_status() -> dict:
    """Cheap status for the UI — never raises."""
    try:
        b = make_backend()
        return {"provider": b.provider, "model": b.model, "kind": b.kind,
                "ready": b.ready, "error": b.error}
    except Exception as e:
        return {"provider": "?", "model": "?", "kind": "?", "ready": False, "error": str(e)}
