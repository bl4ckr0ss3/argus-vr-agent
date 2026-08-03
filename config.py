"""ARGUS central configuration.

All paths and knobs live here so the rest of the codebase never hard-codes a
location. Everything can be overridden with environment variables (see
.env.example) so the same code runs on another host without edits.
"""
from __future__ import annotations

import os
from pathlib import Path

# --- Repo layout -----------------------------------------------------------
ROOT = Path(__file__).resolve().parent
DATASET_DIR = ROOT / "dataset"
CORPUS_DIR = DATASET_DIR / "corpus"
CORPUS_FILE = DATASET_DIR / "corpus.jsonl"
EXEMPLARS_FILE = DATASET_DIR / "exemplars.jsonl"
BENCHMARK_FILE = DATASET_DIR / "benchmark.jsonl"
INDEX_FILE = DATASET_DIR / "bm25_index.json"
# Where detonation results + the review queue are written. Override with
# ARGUS_RUNS to point at a persistent location (e.g. a VMware shared folder on
# the host) so results survive a VM snapshot revert. Pair with ARGUS_STATE for
# the XP ledger / seen-set.
RUNS_DIR = Path(os.environ.get("ARGUS_RUNS", str(ROOT / "runs")))
PROGRESSION_FILE = ROOT / "progression.json"
STATE_DIR = Path(os.environ.get("ARGUS_STATE", str(ROOT / "state")))
# The hunter progression / level-up state (XP, ranks, bug ledger, achievements).
PROGRESSION_FILE = STATE_DIR / "progression.json"

# --- Knowledge source (the "second brain") ---------------------------------
# The Obsidian VR vault that ARGUS mines for its knowledge base.
VAULT_ROOT = Path(os.environ.get("ARGUS_VAULT", r"C:\Second-Brain-Claude"))
VR_DIR = VAULT_ROOT / "Vulnerability Research"

# --- LLM provider ----------------------------------------------------------
# ARGUS is provider-agnostic. It can drive DeepSeek, OpenAI, Anthropic, or any
# OpenAI-compatible endpoint (local Ollama / LM Studio / vLLM). Set
# ARGUS_PROVIDER explicitly, or just set a key and let it auto-detect.
#
# The OpenAI-compatible path (deepseek/openai/custom) is pure stdlib HTTP, so it
# needs NO extra pip packages. Only the "anthropic" provider needs the SDK.
PROVIDER = os.environ.get("ARGUS_PROVIDER", "").strip().lower()
MODEL = os.environ.get("ARGUS_MODEL", "").strip()  # blank -> per-provider default
MAX_TOKENS = int(os.environ.get("ARGUS_MAX_TOKENS", "8000"))
TEMPERATURE = float(os.environ.get("ARGUS_TEMPERATURE", "0.2"))
# Hard ceiling on agent<->model round trips per hunt, so a runaway loop can
# never burn the account unattended.
MAX_STEPS = int(os.environ.get("ARGUS_MAX_STEPS", "40"))
# Deep-hunt context control. On a long hunt the message history grows with every
# tool output; left unbounded it eventually overflows the model's context window
# and the run dies mid-hunt. We keep the task + the N most recent history entries
# verbatim and truncate OLDER tool outputs to OLD_TOOL_CAP chars — the recent
# reasoning stays intact, so the agent can go deep without blowing context.
HISTORY_KEEP_RECENT = int(os.environ.get("ARGUS_HISTORY_KEEP", "10"))
HISTORY_OLD_TOOL_CAP = int(os.environ.get("ARGUS_HISTORY_OLD_CAP", "600"))


def resolve_llm() -> dict:
    """Resolve the active LLM backend from the environment (read live).

    Returns a dict: {provider, kind, base_url, api_key, model}.
      kind == "openai"    -> OpenAI-compatible chat/completions (stdlib HTTP)
      kind == "anthropic" -> Anthropic Messages API (needs the anthropic SDK)
    """
    provider = PROVIDER
    base_url = os.environ.get("ARGUS_BASE_URL", "").strip()
    gen_key = os.environ.get("ARGUS_API_KEY", "").strip()
    ds = os.environ.get("DEEPSEEK_API_KEY", "").strip()
    an = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    oa = os.environ.get("OPENAI_API_KEY", "").strip()
    mk = os.environ.get("MOONSHOT_API_KEY", os.environ.get("KIMI_API_KEY", "")).strip()
    gl = os.environ.get("GLM_API_KEY", os.environ.get("ZHIPU_API_KEY", "")).strip()
    or_key = os.environ.get("OPENROUTER_API_KEY", "").strip()
    ar = os.environ.get("AGENTROUTER_API_KEY", "").strip()
    tr_key = os.environ.get("TOKENROUTER_API_KEY", "").strip()

    if not provider:
        if base_url:
            provider = "custom"
        elif ar:
            provider = "agentrouter"
        elif tr_key:
            provider = "tokenrouter"
        elif or_key:
            provider = "openrouter"  # single key → many models: DeepSeek, GLM, Claude, etc.
        elif ds:
            provider = "deepseek"
        elif gl:
            provider = "glm"
        elif mk:
            provider = "moonshot"
        elif an:
            provider = "anthropic"
        elif oa:
            provider = "openai"
        else:
            provider = "deepseek"

    # DeepSeek exposes its top model as `deepseek-chat` (points at the current
    # flagship). Override with ARGUS_MODEL to pin a specific one, e.g. a
    # V4-PRO / reasoner alias, once you know the exact string DeepSeek serves.
    presets = {
        "deepseek":   {"kind": "openai", "base_url": "https://api.deepseek.com/v1", "api_key": ds or gen_key, "model": "deepseek-v4-pro"},
        "glm":        {"kind": "openai", "base_url": "https://open.bigmodel.cn/api/paas/v4", "api_key": gl or gen_key, "model": "glm-5.2"},
        "moonshot":   {"kind": "openai", "base_url": "https://api.moonshot.ai/v1", "api_key": mk or gen_key, "model": "kimi-k2-0711-preview"},
        "openai":     {"kind": "openai", "base_url": "https://api.openai.com/v1", "api_key": oa or gen_key, "model": "gpt-4o"},
        "anthropic":  {"kind": "anthropic", "base_url": "", "api_key": an or gen_key, "model": "claude-sonnet-5"},
        "openrouter": {"kind": "openai", "base_url": "https://openrouter.ai/api/v1", "api_key": or_key or gen_key, "model": "deepseek/deepseek-v4-pro"},
        # AgentRouter (agentrouter.org) — OpenAI-compatible gateway with a
        # single API key for multiple providers. Base URL docs say /v1
        # for OpenAI-compatible usage. Models are provider-native strings.
        "agentrouter": {"kind": "openai", "base_url": "https://agentrouter.org/v1", "api_key": ar or gen_key, "model": "z-ai/glm-5.2"},
        "tokenrouter": {"kind": "openai", "base_url": "https://api.tokenrouter.com/v1", "api_key": tr_key or gen_key, "model": "moonshotai/kimi-k3-free"},
        "custom":     {"kind": "openai", "base_url": base_url, "api_key": gen_key or oa or ds, "model": "local-model"},
    }

    # OpenRouter model aliases — when provider=openrouter, you can access any
    # model through the same key by prefixing: deepseek/deepseek-v4-pro,
    # zhipuai/glm-4, anthropic/claude-sonnet-5, openai/gpt-4o, etc.
    # Set ARGUS_MODEL to the full OpenRouter path to switch.
    cfg = dict(presets.get(provider, presets["deepseek"]))
    cfg["provider"] = provider
    if base_url:
        cfg["base_url"] = base_url
    # Read ARGUS_MODEL live from the environment (not the module-level constant
    # captured at import time) so values loaded from .env *after* import — e.g.
    # by run.py's _try_dotenv() — still take effect. Without this, setting
    # ARGUS_MODEL=z-ai/glm-5.2 in .env would be silently ignored and the preset
    # default (e.g. deepseek/deepseek-v4-pro) would win.
    live_model = os.environ.get("ARGUS_MODEL", "").strip()
    if live_model:
        cfg["model"] = live_model
    elif MODEL:
        cfg["model"] = MODEL
    return cfg

# --- Tool safety (run_recon) -----------------------------------------------
# run_recon executes a command only if its base binary is on the ACTIVE
# allowlist. There are two profiles, selected by ARGUS_RECON_PROFILE:
#
#   readonly  (DEFAULT, safe-by-default) — inspection tools only. Combined with
#             a strict block list (destructive verbs, redirection, network
#             fetch), so the agent can look but never change system state.
#   offensive (OPT-IN) — the full researcher toolbox: debuggers, network,
#             fuzzers, RE, exploit-dev, interpreters, shells. This is effectively
#             arbitrary code execution on the host it runs on and is NOT
#             sandboxed. Enable ONLY inside an isolated VM:
#                 ARGUS_RECON_PROFILE=offensive
#
# Ship safe: publish/run with `readonly` unless you have deliberately chosen the
# power (and the VM) that `offensive` requires.
RECON_PROFILE = os.environ.get("ARGUS_RECON_PROFILE", "readonly").strip().lower()

# read-only reconnaissance / inspection — nothing here mutates the system when
# paired with _BLOCK_READONLY below.
RECON_READONLY = {
    # Sysinternals + Windows built-ins (static / attribute recon)
    "sigcheck", "accesschk", "sc", "icacls", "whoami", "tasklist",
    "driverquery", "reg", "certutil", "where", "findstr", "dumpbin",
    "link", "python", "file", "strings", "objdump", "readelf", "nm",
    # PE / binary inspection helpers commonly on a researcher box
    "pescan", "pesec", "capa", "floss", "yara", "yara64",
    # read-only Sysinternals inspectors
    "pslist", "psinfo", "psservice", "psloggedon", "psgetsid", "psfile",
    "logonsessions", "listdlls", "handle", "tcpview", "vmmap", "rammap",
    "autoruns", "accessenum", "loadord", "pendmoves",
    # symbol/inspection-only debugger helpers (no live attach)
    "symchk", "ntsymbol", "dumpcap", "tshark",
    # read-only PowerShell / reg *queries* are routed through run_recon too
    # (mutating forms like `reg add` / `Invoke-WebRequest` are blocked below)
    "powershell", "pwsh",
}

# the full opt-in toolbox — everything in readonly PLUS live/offensive tooling.
RECON_OFFENSIVE = RECON_READONLY | {
    # --- Sysinternals suite (full, incl. mutating tools) ---
    "procexp", "procmon", "winobj", "pipelines", "psexec", "pskill",
    "psloglist", "psshutdown", "pssuspend", "ru", "sdelete", "sync",
    "diskmon", "portmon", "tdimon", "regjump", "adrestore", "movefile",
    "adinsight", "dbgview", "zoomit",
    # --- Debuggers & kernel tools (live analysis / attach) ---
    "cdb", "ntsd", "kd", "windbg", "dbgeng", "livekd", "winkd", "dbg",
    "x64dbg", "x32dbg", "ida", "ida64", "ghidra_headless", "radare2", "r2", "binja",
    # --- Network recon (attack surface mapping) ---
    "nmap", "masscan", "curl", "wget", "nslookup", "dig",
    "netcat", "nc", "telnet", "ssh", "ncat",
    # --- Traffic analysis ---
    "wireshark", "tcpdump",
    # --- Web fuzzing ---
    "ffuf", "dirbuster", "gobuster", "wfuzz", "feroxbuster",
    "nuclei", "sqlmap", "burpsuite", "zap",
    # --- Exploitation development ---
    "msfvenom", "nasm", "yasm", "masm", "gcc", "clang", "cl",
    "rc", "make", "cmake", "ninja",
    # --- Hash / password tools ---
    "hashcat", "john", "ophcrack", "mimikatz",
    # --- General utilities / interpreters / shells ---
    "node", "npm", "npx", "perl", "ruby", "php", "java", "javaw",
    "cmd", "bash", "wsl", "msys2", "cygwin",
}

# Substrings that hard-block a command even if the base binary is allowed.
# readonly: refuse anything that mutates state, redirects output, or fetches
# from the network (keeps `reg`/`sc`/`powershell` genuinely read-only).
_BLOCK_READONLY = (
    "remove-item", "rmdir", " del ", "format", "reg delete", "reg add",
    "new-service", "sc create", "sc delete", "sc config", "stop-service",
    "invoke-webrequest", "invoke-restmethod", "iwr ", "curl ", "wget ",
    "-outfile", "start-process", "shutdown", "diskpart", "set-", "new-item",
    ">", ">>", "|",
)
# offensive: only refuse the truly host-destroying commands; the operator has
# explicitly accepted arbitrary execution (in a VM) by choosing this profile.
_BLOCK_OFFENSIVE = ("format c:", "format d:", "diskpart")

if RECON_PROFILE == "offensive":
    RECON_ALLOWLIST = RECON_OFFENSIVE
    RECON_BLOCK_SUBSTRINGS = _BLOCK_OFFENSIVE
else:
    RECON_PROFILE = "readonly"
    RECON_ALLOWLIST = RECON_READONLY
    RECON_BLOCK_SUBSTRINGS = _BLOCK_READONLY

# Max bytes any single tool call may return to the model (keeps context sane).
TOOL_OUTPUT_CAP = int(os.environ.get("ARGUS_TOOL_CAP", "12000"))

# --- Malware triage (STATIC ONLY) ------------------------------------------
# Samples are unpacked here and NEVER executed. run_recon refuses to launch any
# binary under this directory. Handle real samples inside an isolated VM.
QUARANTINE_DIR = Path(os.environ.get("ARGUS_QUARANTINE", str(ROOT / "quarantine")))
# Zip-bomb / resource guards for unpacking untrusted archives.
MAX_UNPACK_BYTES = int(os.environ.get("ARGUS_MAX_UNPACK_BYTES", str(500 * 1024 * 1024)))  # 500 MB total
MAX_UNPACK_FILES = int(os.environ.get("ARGUS_MAX_UNPACK_FILES", "2000"))
MAX_UPLOAD_BYTES = int(os.environ.get("ARGUS_MAX_UPLOAD_BYTES", str(80 * 1024 * 1024)))   # 80 MB archive
# Passwords tried automatically for protected malware archives.
ZIP_PASSWORDS = ["infected", "malware", "virus", "password"]

# --- Autonomous intake (collect -> triage) ---------------------------------
# Any source (MalwareBazaar feed, a honeypot, or you) drops files here; the
# watcher triages each new one statically. Keep this on an isolated VM.
INTAKE_DIR = Path(os.environ.get("ARGUS_INTAKE", str(ROOT / "intake")))
INTEL_DIR = Path(os.environ.get("ARGUS_INTEL", str(ROOT / "intel")))
# MalwareBazaar (abuse.ch) — free API key from https://auth.abuse.ch.
MALWAREBAZAAR_API_KEY = os.environ.get("MALWAREBAZAAR_API_KEY", os.environ.get("ABUSE_CH_API_KEY", ""))
MALWAREBAZAAR_API = os.environ.get("MALWAREBAZAAR_API", "https://mb-api.abuse.ch/api/v1/")
# Where per-sample triage reports are written in the Obsidian vault.
INTEL_VAULT_DIR = VR_DIR / "Malware Intel"

# --- YARA (static rule scanning) -------------------------------------------
# Uses yara-python if importable, else the `yara` CLI binary. Drop .yar files in
# YARA_RULES_DIR. Scans files statically — never executes them.
YARA_RULES_DIR = Path(os.environ.get("ARGUS_YARA_RULES", str(ROOT / "rules")))
YARA_BIN = os.environ.get("ARGUS_YARA_BIN", "yara64")
# Known-benign corpus a rule is scanned against before it can be promoted/enabled:
# if a rule matches anything here it is too broad (false-positive prone). Populate
# with clean system binaries / common apps. Empty -> FP test is skipped (compile
# check still runs). Point at e.g. C:\Windows\System32 for a strong local corpus.
GOODWARE_DIR = Path(os.environ.get("ARGUS_GOODWARE", str(ROOT / "goodware")))

# --- VirusTotal (hash lookups only — ARGUS never uploads samples) ----------
VT_API_KEY = os.environ.get("VT_API_KEY", os.environ.get("VIRUSTOTAL_API_KEY", ""))
VT_API = os.environ.get("VT_API", "https://www.virustotal.com/api/v3")

# --- Web console auth ------------------------------------------------------
# If set, EVERY web request must carry this token (Authorization: Bearer <t>,
# ?token=<t>, or the cookie set on first authed visit). This is REQUIRED to bind
# the console to any non-localhost address: the agent can run shell commands and
# detonate samples, so an unauthenticated network endpoint is effectively a
# remote-code-execution service. Localhost with no token = single-user dev mode.
WEB_TOKEN = os.environ.get("ARGUS_WEB_TOKEN", "").strip()

# --- Production mode / optimization -----------------------------------------
# Set ARGUS_PROFILE=production for faster, leaner pipeline (shorter timeouts,
# smaller captures, parallel processing, auto-cleanup). Default (development)
# runs full-depth analysis with maximum detail.
ARGUS_PROFILE = os.environ.get("ARGUS_PROFILE", "development").strip().lower()
IS_PRODUCTION = ARGUS_PROFILE == "production"

# Detonation speed (seconds). Production = 30s (catches most droppers).
# Development = 600s (catches gated/beaconing samples).
DETONATE_TIMEOUT = int(os.environ.get("ARGUS_DETONATE_TIMEOUT", "30" if IS_PRODUCTION else "600"))

# Parallel samples per detonation batch. Production = 3 concurrent.
# Development = 1 (sequential, full detail).
PARALLEL_DETONATIONS = int(os.environ.get("ARGUS_PARALLEL", "3" if IS_PRODUCTION else "1"))

# Disk retention (days). Production = auto-clean runs older than 7 days.
# Development = keep everything.
RUNTIME_RETENTION_DAYS = int(os.environ.get("ARGUS_RETENTION_DAYS", "7" if IS_PRODUCTION else "0"))

# Model tiering — which model for which task type.
# Production: use cheap model for triage, main model for hunting.
# Development: use main model for everything.
MODEL_TIER = {
    "triage": os.environ.get("ARGUS_MODEL_TRIAGE", "deepseek/deepseek-chat" if IS_PRODUCTION else ""),
    "classify": os.environ.get("ARGUS_MODEL_CLASSIFY", "deepseek/deepseek-chat" if IS_PRODUCTION else ""),
    "hunt": os.environ.get("ARGUS_MODEL_HUNT", ""),
}
