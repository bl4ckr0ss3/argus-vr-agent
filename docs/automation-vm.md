# Building an unencrypted automation VM (for hunt-loop.ps1)

The `scripts/hunt-loop.ps1` orchestrator drives the guest via `vmrun`, which needs
an **unencrypted** VM with **VMware Tools**. This is the one-time setup for a VM
that runs the fully-unattended hunt loop.

Key idea: this VM **never needs the internet during hunting** — the host fetches
inert sample zips and copies them in. So it stays **Host-only** in normal use.

---

## Phase 1 - Create the VM (NO encryption)

- New VM in VMware Workstation: Windows 10/11, **4 GB+ RAM, 2+ cores, 60 GB disk**.
- **Do NOT enable encryption** this time (that's what broke automation before).
- Install Windows. Create a user **`lab`** with a password you'll remember
  (this is the `-GuestPassword` you pass to hunt-loop.ps1).

## Phase 2 - VMware Tools (REQUIRED)

- **VM -> Install VMware Tools**, run the installer in the guest, reboot.
- `vmrun runProgramInGuest`/`copyFileFromHostToGuest` do not work without Tools.

## Phase 3 - Tools + code (temporary NAT, no malware yet)

Set the network adapter to **NAT** for setup downloads only, then in the guest:

```powershell
# git + python
winget install --id Git.Git -e --accept-source-agreements --accept-package-agreements
winget install --id Python.Python.3.12 -e --accept-source-agreements --accept-package-agreements

# the code (public repo, no auth)
git clone https://github.com/bl4ckr0ss3/argus-vr-agent.git C:\argus-vr-agent
cd C:\argus-vr-agent

# analysis tools
New-Item -ItemType Directory -Force C:\Tools | Out-Null
Invoke-WebRequest "https://download.sysinternals.com/files/SysinternalsSuite.zip" -OutFile C:\Tools\sys.zip
Expand-Archive C:\Tools\sys.zip -DestinationPath C:\Tools\Sysinternals -Force
winget install --id WiresharkFoundation.Wireshark -e --accept-source-agreements --accept-package-agreements

# python libs (pyzipper = AES sample unpack; volatility3 = memscan)
pip install yara-python pyzipper volatility3 pytest

# PATH / exec policy / EULA
Set-ExecutionPolicy -Scope Process Bypass -Force
.\scripts\vm-setup.ps1
```

## Phase 4 - Shared folder + persistent output

- **VM -> Settings -> Options -> Shared Folders -> Enable**, add a host folder,
  map it in the guest to `Z:` (or note its path).
- Point ARGUS output at it so results survive reverts:
```powershell
[Environment]::SetEnvironmentVariable("ARGUS_RUNS","Z:\argus-results\runs","User")
```

## Phase 5 - Isolate, verify, snapshot

```powershell
# switch the network adapter back to HOST-ONLY (isolated) - this is the hunting state
python run.py doctor        # want: network mode = detonation (isolated), DETONATION READY
```
- Confirm: procmon/tshark/yara OK, **no API keys**, isolated.
- **Take a snapshot named `CLEANBASELINE`.**

## Phase 6 - Run the orchestrator (on the HOST)

```powershell
# fetch inert zips to a host folder (Defender exclusion first, elevated shell):
#   Add-MpPreference -ExclusionPath "<sampledir>"
cd C:\Users\Ege\Downloads\Claude\argus-vr-agent
$env:MALWAREBAZAAR_API_KEY = "<mb key>"
python run.py fetch --tag RedLineStealer --limit 10

# unattended hunt (no -VmPassword needed - unencrypted):
.\scripts\hunt-loop.ps1 `
    -Vmx "C:\Users\Ege\Documents\Virtual Machines\<vm name>\<vm name>.vmx" `
    -Snapshot CLEANBASELINE `
    -SampleDir ".\intake" `
    -GuestUser lab -GuestPassword "<lab password>"
```

Per sample: revert -> copy in -> autohunt -> results to `Z:` -> revert. Fully hands-off.

## Gotchas

| Symptom | Fix |
|---|---|
| `runProgramInGuest` fails/hangs | VMware Tools not up -> raise `-BootWaitSec 60`/`90` |
| "Incorrect password" | you encrypted it again - don't; or wrong `-GuestPassword` |
| guest "queue empty" | baseline lacks auto-unpack -> `git pull` in guest, re-snapshot |
| `Add-MpPreference` denied | run the host PowerShell as Administrator |
| results not on host | Shared Folder not mapped, or `ARGUS_RUNS` unset in baseline |
