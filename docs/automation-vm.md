# Building the detonation VM for the autonomous hunt loop

A clean, **unencrypted** Windows VM that `scripts/autonomous.ps1` drives via
`vmrun` — no `-vp`, no encrypted-snapshot fragility. This checklist bakes in
every lesson from getting the loop working end-to-end:

- the guest needs **auto-login** (runProgramInGuest can't launch programs with
  no interactive session)
- detonation needs **admin** (procmon loads a driver) → **UAC off** + admin user
- the guest automation session **can't run `cmd.exe`** (blocked) → the scripts
  drive **PowerShell**
- the VMware **shared folder isn't reliable** from that session → results are
  written guest-local and **copied out** by hunt-loop
- the **CLEANBASELINE snapshot must be taken POWERED OFF** (a running-state
  snapshot + hard-stop orphans a delta disk and corrupts the chain)

---

## Phase 1 — create the VM (NO encryption)
- New VM: Windows 10/11, **4 GB+ RAM, 2+ cores, 60 GB disk**.
- **Do NOT enable encryption.**
- Install Windows. Create a **local admin** user `lab` with password `12345`
  (or your own — pass them to the scripts).

## Phase 2 — VMware Tools (REQUIRED)
- **VM → Install VMware Tools**, run the installer in the guest, reboot.
- Without Tools, `vmrun` can't copy files or run programs in the guest.

## Phase 3 — tools + code (temporary NAT)
Set the adapter to **NAT** for setup only, then in the guest (elevated PowerShell):
```powershell
winget install --id Git.Git -e --accept-source-agreements --accept-package-agreements
winget install --id Python.Python.3.12 -e --accept-source-agreements --accept-package-agreements
git clone https://github.com/bl4ckr0ss3/argus-vr-agent.git C:\argus-vr-agent
cd C:\argus-vr-agent
pip install yara-python pyzipper volatility3 pytest

# analysis tools into C:\Tools (procmon, tshark) and ON PATH
New-Item -ItemType Directory -Force C:\Tools | Out-Null
Invoke-WebRequest "https://download.sysinternals.com/files/SysinternalsSuite.zip" -OutFile C:\Tools\sys.zip
Expand-Archive C:\Tools\sys.zip -DestinationPath C:\Tools -Force
winget install --id WiresharkFoundation.Wireshark -e --accept-source-agreements --accept-package-agreements
# add C:\Tools + Wireshark to the MACHINE PATH so elevated/automation sessions see them:
[Environment]::SetEnvironmentVariable("PATH",
  [Environment]::GetEnvironmentVariable("PATH","Machine") + ";C:\Tools;C:\Program Files\Wireshark", "Machine")
```

## Phase 4 — auto-login + UAC off (the critical bits)
Elevated PowerShell in the guest:
```powershell
# auto-login (creates a desktop session on every boot - required for runProgramInGuest)
$w = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
Set-ItemProperty $w AutoAdminLogon  "1"
Set-ItemProperty $w DefaultUserName "lab"
Set-ItemProperty $w DefaultPassword "12345"
Set-ItemProperty $w DefaultDomainName $env:COMPUTERNAME
# disable UAC so detonation runs elevated (procmon needs admin)
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" EnableLUA 0
# stop Defender from eating samples (isolated VM, so this is fine)
Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
Add-MpPreference -ExclusionPath "C:\argus-vr-agent" -ErrorAction SilentlyContinue
```
**Reboot** and confirm it lands **straight on the desktop** (no password prompt).

## Phase 5 — isolate, verify, then snapshot POWERED OFF
```powershell
python C:\argus-vr-agent\run.py doctor    # want: procmon/tshark/yara OK, no keys
```
- Set the network adapter to **Host-only** (isolated — this is the hunting state).
- **Shut the VM DOWN** (Start → Power → Shut down). Fully powered off.
- Then take the snapshot from the HOST, powered off:
```powershell
$vmx="C:\Users\Ege\Documents\Virtual Machines\<vm name>\<vm name>.vmx"
$vr="C:\Program Files\VMware\VMware Workstation\vmrun.exe"
& $vr -T ws snapshot $vmx CLEANBASELINE
```
> A **powered-off** snapshot reverts cleanly forever. Never snapshot while
> running for an automation baseline — that is what corrupted the last VM.

## Phase 6 — run it (on the HOST, two terminals)
**Terminal 1 — publisher:**
```powershell
cd C:\Users\Ege\Downloads\Claude\argus-vr-agent
$env:ARGUS_RUNS="C:\argus-results\runs"
$env:VT_API_KEY="<your VT key>"
$env:ARGUS_SITE_DIR="C:\Users\Ege\sites\0xblack.dev"
$env:ARGUS_SITE_SUBDIR="static/findings"; $env:ARGUS_SITE_URL="https://0xblack.dev"
$env:ARGUS_AUTOPUBLISH="1"
python run.py web
```
**Terminal 2 — hunter (unencrypted → no -VmPassword):**
```powershell
cd C:\Users\Ege\Downloads\Claude\argus-vr-agent
$env:MALWAREBAZAAR_API_KEY="<your MB key>"
.\scripts\autonomous.ps1 -Vmx "C:\Users\Ege\Documents\Virtual Machines\<vm name>\<vm name>.vmx" -GuestPassword 12345
```
(If you keep the VM encrypted, add `-VmPassword <encryption password>`.)

## Gotchas (all now handled by the scripts)
| Symptom | Cause / fix |
|---|---|
| every program "exited with code 1" | no auto-login → do Phase 4, re-snapshot |
| detonate fails on procmon | UAC on → set `EnableLUA=0`, reboot, re-snapshot |
| "network location cannot be reached" | shared folder — scripts write guest-local + copy out |
| "A required file was not found" on revert | snapshot was taken **running** then hard-stopped — always snapshot **powered off** |
| `git pull` in guest needs internet | flip to NAT briefly, pull, flip back to Host-only, re-snapshot |
