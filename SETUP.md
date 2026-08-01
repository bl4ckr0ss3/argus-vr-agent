# ARGUS Setup — from zero to hunting

Two machines, two jobs. Keep them separate and everything is easy:

- **HOST** — holds your API keys; runs the LLM agent, `fetch`, `enrich`, `publish`.
- **ANALYSIS VM** — isolated, **no credentials**; runs `detonate` / `autohunt`.

The malware only ever *executes* in the VM. The VM never holds a key. That's the
whole safety model.

---

## Part 1 — one-time VM setup

### 1. Install the tools (download once)
| Tool | Where to get it | Put it |
|------|-----------------|--------|
| Sysinternals Suite (procmon) | microsoft.com/sysinternals | extract to `C:\Tools\Sysinternals` |
| Wireshark (tshark) | wireshark.org | default install (`C:\Program Files\Wireshark`) |
| Python 3.11+ | python.org | default |
| *(optional)* yara-python | `pip install yara-python` | enables real YARA scanning |
| *(optional)* FakeNet-NG | github.com/mandiant/flare-fakenet-ng | `C:\Tools\fakenet-ng` — simulated internet for detonation |

### 2. Get the code and configure the environment
Elevated PowerShell in the VM:
```powershell
cd C:\argus-vr-agent
git pull
Set-ExecutionPolicy -Scope Process Bypass -Force
.\scripts\vm-setup.ps1
```
`vm-setup.ps1` puts the tools on PATH (correctly), sets the execution policy,
accepts the Procmon EULA, and asserts the VM holds no API keys. If a tool isn't
found, pass its folder: `.\scripts\vm-setup.ps1 -SysinternalsDir "C:\path"`.

### 3. Verify readiness
```powershell
python run.py doctor
```
Target state:
```
[ OK ]  procmon        C:\Tools\Sysinternals\Procmon.exe
[ OK ]  tshark         C:\Program Files\Wireshark\tshark.exe
[ OK ]  credentials    no LLM credentials (detonation-safe)
DETONATION   : READY
```

### 4. Snapshot the VM as `clean-baseline`
In your hypervisor, snapshot now. This is your per-sample reset point — tools
installed, isolated, keyless, code current. You revert to it before each sample.

---

## Part 2 — the two network modes (never mix them)

`doctor` reports which one you're in.

| Mode | Network | Use for | How |
|------|---------|---------|-----|
| **Collection** | real internet | `fetch` | adapter = NAT, **no malware running** |
| **Detonation** | isolated (or FakeNet) | `detonate` / `autohunt` | adapter = Host-only |

**Never run malware with real internet** — the sample can reach its C2, exfiltrate,
and attack others using your IP. To see network behavior safely, use **FakeNet**
(`$env:ARGUS_FAKENET="1"`), which fakes the internet locally so nothing leaves.

---

## Part 3 — getting samples in

**Option A (recommended) — fetch on the host, carry them in:**
```powershell
# HOST (has internet), key set:
python run.py fetch --limit 5          # password-zips land in intake\
# copy those .zip files into the VM's intake\  (they're inert until detonated)
```

**Option B — briefly go online in the VM:**
```powershell
# switch VM adapter to NAT
python run.py doctor                    # COLLECTION READY
python run.py fetch --limit 5
# switch adapter back to Host-only / revert to clean-baseline BEFORE detonating
```

---

## Part 4 — the daily loop

```powershell
# revert to clean-baseline (isolated), samples in intake\
python run.py doctor                    # confirm DETONATION READY
python run.py autohunt --once           # detonate -> verdict -> XP -> YARA rule -> draft
python run.py progression --leaderboard # your standing
```

Single sample instead of the queue:
```powershell
python run.py detonate C:\Users\lab\Downloads\sample.exe
```

Re-analyze a run whose verdict came back INCONCLUSIVE (converts a big procmon log):
```powershell
python run.py reanalyze C:\argus-vr-agent\runs\dynamic\<folder>
```

---

## Part 4b — rootkit / bootkit research (`bootscan`)

The detonation loop can't see rootkits/bootkits — a kernel rootkit hides from the
live OS, and a bootkit fires at boot before the OS exists. Use **differential
boot-chain forensics** instead (Admin shell, in the VM):

```powershell
python run.py bootscan --baseline    # BEFORE: hashes MBR/VBR/ESP, BCD, Secure Boot, drivers
python run.py detonate C:\samples\rk.sys   # or run the dropper
# ... REBOOT the VM (the bootkit payload fires here) ...
python run.py bootscan --compare     # AFTER: diff -> boot-chain tampering + new drivers
```

Flags MBR/VBR modification (MBR bootkits), ESP `.efi` changes (UEFI bootkits like
ESPecter/BlackLotus), new boot-start/BYOVD drivers, `testsigning`/`nointegritychecks`
in the BCD, and Secure Boot being turned off. Read-only — it never writes the boot chain.

Pair it with **`memscan`** — Volatility3 cross-view memory forensics, which catches
a kernel rootkit that hides from the live OS (it unlinks its objects, but they're
still in raw memory):

```powershell
pip install volatility3
# get a dump: suspend the VM (VMware writes a .vmem), or acquire live:
python run.py memscan --acquire dump.raw
python run.py memscan dump.raw          # psscan vs pslist, modscan vs modules, malfind
```
Flags **hidden processes** (in `psscan` but unlinked from `pslist` = DKOM),
**hidden drivers** (in `modscan` but not `modules`), and **injected code**
(`malfind` RWX regions) — the exact signatures a kernel rootkit leaves in memory.

For firmware/SPI: **CHIPSEC**; for live kernel inspection: **WinDbg** kernel debugging.
Use a **UEFI VM** (not legacy BIOS) for UEFI-bootkit study, and confirm your
hypervisor snapshots NVRAM so a revert cleans a firmware-variable infection.

---

## Part 5 — on the HOST (keys live here)

```powershell
python run.py enrich <run_dir>          # add VirusTotal consensus to a verdict
python run.py publish --list            # review-queue drafts
python run.py publish <draft> --approve
python run.py publish <draft> --to vt,twitter,linkedin --confirm
python run.py hunt "..."                # LLM-driven vuln research (needs a model key)
```

---

## Troubleshooting (the things that actually bite)

| Symptom | Cause | Fix |
|---------|-------|-----|
| `where.exe tshark` finds nothing | PATH not set / bad separator | re-run `vm-setup.ps1`; use `where.exe`, not `where` |
| verdict `INCONCLUSIVE (procmon CSV unavailable)` | procmon off PATH, or huge log timed out | `doctor` to check PATH, then `reanalyze <dir>` |
| `fetch` returns a **FakeNet** HTML page | sinkhole intercepting traffic | `Stop-Process -Name fakenet -Force`; you need real internet to fetch |
| `fetch` -> `getaddrinfo failed` | VM has no internet (host-only) | switch to NAT, or fetch on the host |
| `DETONATION BLOCKED — API key present` | a key leaked into the VM | remove it; the VM must be keyless |
| `.ps1` won't run | execution policy | `Set-ExecutionPolicy -Scope Process Bypass -Force` |
| PowerShell parse error in a `.ps1` | non-ASCII char | keep repo scripts ASCII-only |

**Golden rule:** collect online with no malware running → detonate isolated →
never both at once. `python run.py doctor` tells you which mode you're in.
