# ARGUS — Autonomous VR Agent (kernel CVE + bug bounty + malware intel)

A Nebula/XBOW-style vulnerability-research agent — now
covering the full spectrum: **Windows kernel LPE for CVEs**, **web bug bounty**
(SSRF, IDOR, SQLi, XSS, auth bypass), **binary RE**, and **autonomous malware
triage**. It is **not** a fine-tuned model — like the real labs, it is a
*frontier model wrapped in an agentic scaffold*: Claude/DeepSeek/OpenAI driving
12 tools over a knowledge base, held to the `critical-vuln-research` four-gate
verification bar so it never reports an unproven bug.

```
          ┌──────────────────────────────────────────────────┐
          │   DeepSeek / Claude / OpenAI  (argus/agent.py)    │
          └─────────────────┬────────────────────────────────┘
                            │ 12 tools
   ┌──────────┬────────────┬┴───────┬─────────────┬───────────┬──────────────┐
   ▼          ▼            ▼        ▼             ▼           ▼              ▼
retrieve_   run_recon    read_file/ list_dir/    grep        record_       http_request
knowledge   (100+ bin)   list_dir               (regex)     candidate      (web bounty)
   │          │           │         │            │           │ (→ vault)     │
   ▼          ▼           ▼         ▼            ▼           ▼ + XP system  ▼
 BM25     kernel_research  network_recon    triage_report  unpack_sample   yara_scan
(RAG)    (drivers/IOCTL)  (port scan)       (malware RE)   (zip handling)  (rules)
   │
   ▼
dataset/corpus.jsonl  ◄── built from  C:\Second-Brain-Claude\Vulnerability Research
```

## Why this shape
Labs like Nebula, XBOW, and Google Big Sleep don't train their own base models —
they orchestrate a frontier model over security tools + a knowledge base + an
eval harness. The "dataset" is retrieval context, few-shot exemplars, and a
benchmark to measure the agent. That is exactly what this repo is. A local
fine-tune is a possible *phase 2* lever (e.g. triaging decompiler output), not
where the capability comes from.

## Providers (bring your own model)
ARGUS is provider-agnostic — it auto-detects from whichever key you set, or
force it with `ARGUS_PROVIDER`:

| Provider  | kind      | needs pip?        | example model     |
|-----------|-----------|-------------------|-------------------|
| deepseek  | openai    | no (stdlib HTTP)  | `deepseek-chat`, `deepseek-reasoner` (track the current flagship → V4-PRO) |
| moonshot  | openai    | no (stdlib HTTP)  | `kimi-k2-0711-preview` (set the K3 alias via `ARGUS_MODEL`) |
| openai    | openai    | no (stdlib HTTP)  | `gpt-4o`          |
| custom    | openai    | no (stdlib HTTP)  | local Ollama / LM Studio / vLLM |
| anthropic | anthropic | `pip install anthropic` | `claude-sonnet-5` |

Long automated hunts on DeepSeek V4-PRO: set `DEEPSEEK_API_KEY` and (optionally)
`ARGUS_MODEL` to the exact alias, then `python run.py hunt "…"` or drive it from
the web console. Every recorded lead levels the agent up (see below). The
OpenAI-compatible backends now retry transient rate-limit/5xx blips with backoff,
so a 40-step run survives a hiccup instead of dying mid-hunt.

The OpenAI-compatible path is pure standard library, so DeepSeek (or a local
model) runs with **no extra packages** — see `.env.example`.

## Dynamic analysis & the autonomous detection pipeline
The most developed half of ARGUS: **detonate a sample in a VM → get a scored,
corroborated verdict → auto-grow YARA detection → publish findings** — human-gated
where it matters. This half makes **zero LLM calls**, so it runs **keyless inside
the detonation VM** (the machine that runs malware must hold no credentials).

### Detonate — dynamic behavioral analysis
```bash
python run.py detonate C:\samples\thing.exe --timeout 120   # VM ONLY
```
Executes the sample and **streams each stage live**: static ID + YARA scan,
baseline registry/filesystem snapshots, Procmon + network capture (on the real
interface, auto-selected), timed execution, then an auto-computed verdict — no
hand-analysis of raw artifacts. Everything lands in `runs/dynamic/<sha>_<ts>/`
(report + `findings.json` + pcap + procmon log).

- **Credential guard** — refuses to detonate while *any* API key is reachable in
  the environment; a detonated binary can read and exfiltrate them.
- **Honest telemetry** — auto-picks the capture interface (no blind `-i 1`), and
  reports FakeNet as running only if it actually stayed up.

### The triangulated verdict
Every detonation is scored from three independent evidence sources, so no single
blind spot decides the call:

| Source   | Signal                                   | Catches                        |
|----------|------------------------------------------|--------------------------------|
| dynamic  | persistence, network, drops, child procs | runtime behavior               |
| static   | `yara-match` (highest weight)            | known families / signatures    |
| external | VirusTotal AV consensus                  | the wider world's ground truth |

Each verdict carries a **0–100 confidence** score + label and **MITRE ATT&CK**
technique tags (T1547.001, T1543.003, T1071, T1105, T1027.002…). VirusTotal
enrichment (`python run.py enrich <run_dir>`, host-side) reconciles disagreements:
a clean heuristic that VT flags is escalated; a "suspicious" heuristic that VT
contradicts (0 detections) is demoted to a likely false positive.

### Autohunt — the self-running loop
```bash
python run.py autohunt --once      # drain intake/ ; --once or loop
```
`queue → detonate → verdict → XP ledger → stage a candidate YARA rule → human-gated
review-queue draft`. Idempotent by SHA-256, and it **halts** if it ever sees
credentials in the VM. Suspicious samples earn XP (reproduced + impact gates) and
auto-stage a YARA rule for their family.

### Detection engineering — make & collect YARA rules
```bash
python run.py yara --gen C:\samples\mal.exe --save   # derive a rule from a sample
python run.py rules --fetch signature-base           # pull a community ruleset
python run.py rules --enable signature-base          # trust it -> now scanned
python run.py yara --check ARGUS_mal                 # quality gate on demand
python run.py yara --promote ARGUS_mal               # move a rule live (gated)
```
Three ways rules enter **live** detection, each with a gate so a bad rule can't
poison triage:

| Origin                    | Stages in            | Goes live via            |
|---------------------------|----------------------|--------------------------|
| curated (yours)           | `rules/*.yar`        | tracked in git           |
| auto-generated (hunts)    | `rules/generated/`   | `yara --promote` (gated) |
| community (fetched)       | `rules/community/`   | `rules --enable`         |

The **quality gate** (`argus/rule_quality.py`) compile-tests a rule and scans it
against a known-benign corpus (`ARGUS_GOODWARE`, e.g. `C:\Windows\System32`);
a rule that matches goodware is too broad and `--promote` refuses it (`--force`
to override). The engine also tolerates a broken community rule — it falls back
to per-file compilation instead of silently disabling all detection.

### Publish — human-gated disclosure
```bash
python run.py publish --list
python run.py publish <draft> --approve                 # after reviewing writeup.md
python run.py publish <draft> --to vt,twitter,linkedin  # DRY RUN
python run.py publish <draft> --to vt,twitter,linkedin --confirm
```
**Nothing auto-posts.** Two deliberate human steps (approve → publish), dry-run by
default, and a hard refusal to publish a "malware" claim that VirusTotal
contradicts (a wrong accusation is defamatory and can't be un-posted). Adapters
(stdlib): a VT comment on the hash (never uploads a sample), Twitter v2 via OAuth
1.0a, LinkedIn via OAuth2. Credentials are **host-only** — never in the VM.

### The VM workflow
```
scripts\vm-setup.ps1  →  python run.py doctor  →  snapshot 'clean-baseline'
per sample:  revert clean-baseline  →  git pull  →  python run.py doctor  →  detonate / autohunt
```
`python run.py doctor` is the preflight: it verifies tools are on PATH, the VM
holds no credentials, and reports the current **network mode** — COLLECTION
(internet up → `fetch` works) vs DETONATION (isolated/FakeNet → safe to run
malware). The two are mutually exclusive by design; doctor tells you which one
you're in so you never fetch sinkholed or detonate online.
`vm-setup.ps1` puts tools on PATH, sets the exec policy, accepts the Procmon EULA,
and asserts the VM holds no credentials. Keys live on the **host** (where `enrich`
/ `publish` / the LLM agent run); the VM is credential-free and disposable.

### Tested
```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -q          # 36 tests, all green
```
Covers the verdict engine's false-positive regressions (benign temp writes, the
Services-hive snapshot flood, YARA overrides), the publish safety gates, rule
generation, community fetch, and the quality gate.

## Layout
```
config.py                 all paths + knobs (env-overridable)
argus/
  agent.py                Claude tool-use loop (hard step cap)
  prompts.py              system doctrine (the 4-gate methodology) + few-shot
  rag/index.py            pure-Python BM25 retriever (no native deps)
  tools/
    knowledge.py          retrieve_knowledge  — RAG over the vault
    filesystem.py         read_file / list_dir / grep  (read-only)
    shell.py              run_recon  — allowlisted, read-only recon only
    findings.py           record_candidate — writes leads into vault Process/
    tools/dynamic.py      detonate — dynamic analysis + triangulated verdict
  autohunt.py             self-running queue → detonate → verdict → review loop
  progression.py          XP / ranks / bug ledger / achievements
  yara_engine.py          static YARA scanning (resilient compile)
  yara_gen.py             generate + collect + promote YARA rules
  rules_fetch.py          fetch/enable community YARA rulesets
  rule_quality.py         compile + goodware false-positive quality gate
  intel/virustotal.py     VT hash-lookup enrichment (never uploads)
  publish.py              human-gated VT / Twitter / LinkedIn disclosure
scripts/vm-setup.ps1      one-shot analysis-VM setup (PATH / EULA / key check)
tests/                    pytest suite (36 tests)
dataset/
  build_dataset.py        mine vault -> corpus / exemplars / benchmark
  corpus.jsonl            (generated) retrieval chunks
  exemplars.jsonl         (seeded, editable) good hunting moves
  benchmark.jsonl         (seeded, editable) scored eval questions
eval/evaluate.py          score the agent vs the benchmark
web/
  server.py               zero-dependency stdlib HTTP server + SSE streaming
  static/index.html       single-file terminal/ops-panel console
run.py                    CLI: doctor jobs selftest index retrieve ask hunt web triage
                               fetch watch detonate reanalyze ioc sigma bootscan
                               memscan autohunt enrich yara rules publish progression collab
```

## Web console
A browser console (terminal/ops-panel aesthetic) that streams the agent's
reasoning and tool calls live over Server-Sent Events. No Flask — pure stdlib,
so it runs under any interpreter that has `anthropic`.

```bash
python run.py web            # -> http://127.0.0.1:8765
```
- **Run a hunt / ask** — streams every step, tool call, tool result, and the
  final report as it happens.
- **Targets tab** — reads your vault `Targets.md` queue and shows each target as
  a card with a status badge; one click on **HUNT THIS** fills the task from the
  target's surface + open questions and launches a streamed hunt.
- **Triage tab** — drop a sample/zip; it's uploaded to `quarantine/` and a static
  malware triage streams live (static only, never executed).
- **Panel tab** — the hunter dossier: level, rank sigil, XP bar, the full ledger
  of every hunted bug (with per-gate progress pips), achievements, and a live
  activity feed. XP toasts pop in real time as the agent records candidates.
- **Knowledge-base search** — BM25 RAG over the vault; works even with no API
  key (great for a quick offline sanity check).
- **Status** — corpus size, benchmark count, provider/model, and whether the API
  is ready (shows a clear banner naming the missing key).

## Desktop tray app (Windows / macOS / Linux)
ARGUS ships as a proper desktop application. The system-tray icon gives you
right-click control: open the console, start/stop the server, view status.

```bash
pip install pystray pillow        # optional — tray icon
python argus_tray.py              # console + tray
pythonw argus_tray.py             # tray only, no console (Windows .pyw)
```

Without pystray the web server still starts — you just get a console instead of
the tray icon. The icon is generated programmatically (no binary image files).

## Level-up system (gamified progression)
ARGUS keeps score. Every `record_candidate` call feeds `argus/progression.py`,
which awards XP, tracks the bug in a persistent ledger (`state/progression.json`),
unlocks achievements, and ranks the operator up through named tiers
(Initiate → Recon → Operator → Breaker → Exploiter → Zero-Day Hunter → Apex Ghost).

- **XP is earned by real progress, not activity.** A new lead pays a base; each
  verification gate genuinely passed pays more; proving all four gates is the
  jackpot. High-impact classes (RCE/SYSTEM/LPE) carry a severity multiplier.
- **No farming.** XP is keyed to a bug *fingerprint* — re-logging the same lead
  pays nothing; only a newly-passed gate pays out the delta. This lines up
  exactly with the four-gate methodology: the agent levels up by *confirming*
  bugs, not by generating candidates.
- The model sees its own XP/level feedback in each tool result, and the web
  **Panel** renders the whole dossier. State survives across runs, so long
  automated DeepSeek hunts compound into a visible track record.

## Setup
```bash
pip install -r requirements.txt
cp .env.example .env             # add your DEEPSEEK_API_KEY / ANTHROPIC_API_KEY
python dataset/build_dataset.py   # or: python run.py index

# Optional: desktop tray icon
pip install pystray pillow
python argus_tray.py
```

## Use
```bash
# RAG only — no API key needed, great for sanity checks:
python run.py retrieve "named pipe DACL LPE"

# Short Q&A (few tool steps):
python run.py ask "What must I verify to turn the Vendor Updater pipe into a confirmed LPE?"

# Full hunt — kernel CVE, web bounty, or binary RE (auto-detected):
python run.py hunt "Audit AntiCheatSvc.exe for a standard-user -> SYSTEM LPE"
python run.py hunt "Find SSRF/IDOR in https://api.target.com and report critical bugs"
python run.py hunt "Audit mydriver.sys IOCTL surface for a kernel LPE that gets a CVE"

# Measure the agent against the benchmark:
python eval/evaluate.py            # keyword coverage
python eval/evaluate.py --judge    # + LLM-judged correctness

# Drive it all from the browser console:
python run.py web                  # -> http://127.0.0.1:8765

# Or use the desktop tray icon:
python argus_tray.py               # -> system tray + browser console

# Measure the agent against the benchmark:
python eval/evaluate.py            # keyword coverage
python eval/evaluate.py --judge    # + LLM-judged correctness

# Or drive it all from the browser console:
python run.py web                  # -> http://127.0.0.1:8765
```

## Malware triage (static only)
ARGUS can triage a suspicious sample — **statically, never executed**:

```bash
python run.py triage C:\path\to\sample.zip     # CLI
# or: web console -> TRIAGE tab -> drop the file
```

It unpacks the archive into `quarantine/` (zip-slip + zip-bomb guarded, auto-tries
`infected`/`malware` passwords), then reports hashes (md5/sha1/sha256), file type,
PE metadata (arch, timestamp, sections + entropy, imported DLLs), suspicious-API
surface, and extracted IOCs (URLs, IPs, domains, registry keys, paths, mutexes) —
and writes an analyst summary with a verdict and dynamic-analysis next steps.

> ⚠ **Run real samples inside an isolated VM** (host-only / no network, snapshot
> first). ARGUS only parses bytes — it never runs the sample, and `run_recon`
> refuses to execute anything under `quarantine/` — but analysing live malware on
> your host is never worth the risk. The whole tool is portable Python; copy it
> into the VM and set your key there.

## Autonomous collection → triage (malware intel)
Any source drops files into `intake/`; the **watcher** unpacks + statically
triages each new sample **for free** (no LLM), writes a per-sample report to the
vault (`Malware Intel/Reports/`), appends `intel/ledger.jsonl`, and regenerates
`Malware Intel/Dashboard.md`. Add `--llm` to also get an ARGUS narrative summary.

```bash
# collect from the wild (VM ONLY — downloads live malware):
python run.py fetch --limit 25            # MalwareBazaar recent
python run.py fetch --tag AgentTesla      # by family

# autonomously triage whatever lands in intake/ (static, free):
python run.py watch                       # poll loop
python run.py watch --once --llm          # one pass + LLM summaries
```

Collection sources (all just drop files into `intake/` — see `intake/README.md`):
- **MalwareBazaar feed** (built in; free abuse.ch key → `MALWAREBAZAAR_API_KEY`).
- **Honeypot** (Dionaea / Cowrie / T-Pot) — rsync captured payloads into `intake/`.
- **Manual** — drop a file and run the watcher.

> ⚠ **VM only.** `fetch` downloads live malware and a honeypot catches it. Run the
> whole pipeline inside an isolated VM (host-only/no-network, outbound sinkholed
> with INetSim/FakeNet, snapshot). Never expose a real Windows XP box to the
> internet as the honeypot — it becomes a launchpad against others. XP's place is
> the **detonation sandbox** (dynamic analysis via CAPE/Cuckoo), not the collector.

## The four gates (hard-wired into the agent)
A candidate is **not** a finding until ALL hold:
1. **Root cause** — the exact flaw, not a symptom.
2. **Reproduced** — a minimal deterministic PoC/trigger.
3. **Impact proven** — the real primitive / privilege / RCE demonstrated.
4. **Scope-checked** — in scope and genuinely security-relevant.

ARGUS has **no** PoC-execution or debugger tool in v0, so gates 2–3 are handed
off to Muhammed with the exact experiment to run. This is deliberate: it keeps the
false-positive rate at zero and keeps a human on the trigger.

## Safety
- `run_recon` executes only base binaries on `config.RECON_ALLOWLIST` (all
  read-only inspection tools) and refuses any command containing a destructive
  verb, redirection, or network fetch.
- The agent never runs exploits, attaches debuggers, or mutates the target.
- `record_candidate` only ever *creates* new notes in `Process/` (never
  overwrites), each with the gate checklist unfilled unless genuinely proven.

## Roadmap
- **Agent scaffold** — RAG + recon tools + eval + provider-agnostic backends. ✅
- **Gamified progression** — XP / ranks / bug ledger / achievements. ✅
- **Static malware triage** + autonomous intake watcher. ✅
- **Dynamic analysis pipeline** — detonate with live streaming, credential guard,
  auto interface selection. ✅
- **Triangulated verdict** — dynamic behavior + YARA + VirusTotal, with
  confidence scoring and MITRE ATT&CK tags. ✅
- **Autohunt** — self-running queue → verdict → ledger → review-queue loop. ✅
- **Detection engineering** — YARA rule generation, community fetch, and a
  compile + goodware false-positive quality gate. ✅
- **Human-gated publishing** — VT comment / Twitter / LinkedIn with a VT-veto. ✅
- **Test suite** — 36 tests over the verdict engine, publish gates, and rules. ✅

### Next levers
- **Web panel** unifying the review queue + rule queues + XP HUD.
- **`rules --update`** to refresh fetched community sources on a schedule.
- **RE tooling** — wire Ghidra/x64dbg MCP servers in as agent tools.
- **Loop-until-dry hunting** with adversarial self-verification of each candidate.
- **phase 2 (optional):** fine-tune a small local model on the curated dataset
  for a narrow, high-volume subtask (e.g. decompiler-output triage).
