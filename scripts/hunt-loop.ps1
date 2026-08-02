#requires -Version 5
<#
    ARGUS host-side hunt orchestrator (VMware, via vmrun).

    Runs the whole detonation cycle unattended, WITHOUT ever giving the guest
    internet: it copies sample zips INTO the isolated VM, runs autohunt, and
    (via ARGUS_RUNS pointing at a shared folder) the results land on the host.
    Each sample gets its own revert -> detonate -> revert, so a destructive
    sample (ransomware/worm) can't corrupt the others.

    PREREQUISITES (one time):
      * VMware Workstation/Player with vmrun.exe
      * VMware Tools installed in the guest (needed for runProgramInGuest)
      * The CLEANBASELINE snapshot has: the LATEST argus code (git pull'd, so
        auto-unpack + ARGUS_RUNS work), tools on PATH, NO credentials, Host-only.
      * A VMware Shared Folder mapped in the guest (e.g. Z:\argus-results) so
        results persist to the host; set ARGUS_RUNS to it in the baseline.

    USAGE (on the HOST):
      # 1. fetch inert sample zips to a host folder (host has internet + MB key):
      #    e.g. run fetch on the host, or copy zips from anywhere, into -SampleDir
      # 2. run the loop:
      .\scripts\hunt-loop.ps1 `
          -Vmx "C:\Users\Ege\Documents\Virtual Machines\Windows 11 x64\Windows 11 x64.vmx" `
          -Snapshot CLEANBASELINE `
          -SampleDir "C:\argus-samples" `
          -GuestUser lab -GuestPassword "PASSWORD"
#>
param(
    [Parameter(Mandatory)] [string]$Vmx,
    [string]$Snapshot   = "CLEANBASELINE",
    [Parameter(Mandatory)] [string]$SampleDir,          # host folder of .zip samples
    [Parameter(Mandatory)] [string]$GuestUser,
    [Parameter(Mandatory)] [string]$GuestPassword,
    [string]$GuestRepo  = "C:\argus-vr-agent",
    [string]$GuestIntake= "C:\argus-vr-agent\intake",
    [string]$ArgusRuns  = "Z:\argus-results\runs",      # (legacy/unused - results now copied out)
    [string]$HostRunsDir= "C:\argus-results\runs",      # host dir the web Autopilot reads
    [int]$BootWaitSec   = 45,                            # seconds to let the guest + Tools come up
    [string]$Vmrun      = "",                            # auto-detected if blank
    [string]$VmPassword = ""                             # VM ENCRYPTION password (if the VM is encrypted)
)

$ErrorActionPreference = "Stop"

function Find-Vmrun {
    if ($Vmrun -and (Test-Path $Vmrun)) { return $Vmrun }
    $c = @(
        "C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe",
        "C:\Program Files\VMware\VMware Workstation\vmrun.exe",
        "C:\Program Files (x86)\VMware\VMware Player\vmrun.exe"
    )
    foreach ($p in $c) { if (Test-Path $p) { return $p } }
    $g = (Get-Command vmrun -ErrorAction SilentlyContinue).Source
    if ($g) { return $g }
    throw "vmrun.exe not found - pass -Vmrun <path>"
}

$VMRUN = Find-Vmrun
# Base options on EVERY vmrun call. -vp is the VM ENCRYPTION password (required
# for encrypted VMs); without it vmrun prompts interactively and the script hangs.
$base  = @("-T", "ws")
if ($VmPassword) { $base += @("-vp", $VmPassword) }
$auth  = $base + @("-gu", $GuestUser, "-gp", $GuestPassword)

function VM([string[]]$vmArgs) {
    $out = & $VMRUN @vmArgs 2>&1
    if ($LASTEXITCODE -ne 0) { throw ("vmrun failed: " + ($out -join ' ')) }
    $out
}
function VMquiet([string[]]$vmArgs) { & $VMRUN @vmArgs 2>&1 | Out-Null }

$samples = Get-ChildItem -Path $SampleDir -Filter *.zip -File
if (-not $samples) { Write-Host "No .zip samples in $SampleDir"; exit 1 }
Write-Host "== ARGUS hunt-loop: $($samples.Count) sample(s) ==" -ForegroundColor Cyan

foreach ($s in $samples) {
    Write-Host "`n--- $($s.Name) ---" -ForegroundColor Yellow
    try {
        Write-Host "  revert -> $Snapshot"
        VM ($base + @("revertToSnapshot",$Vmx,$Snapshot)) | Out-Null
        Write-Host "  start (headless)"
        VM ($base + @("start",$Vmx,"nogui")) | Out-Null
        # Wait for an interactive DESKTOP session (explorer.exe). runProgramInGuest
        # returns a generic 'exit code 1' for every program until a user is logged
        # in, so the baseline MUST auto-login. Poll instead of a fixed sleep.
        Write-Host "  waiting for desktop session (auto-login)..."
        $sessionUp = $false
        $deadline = (Get-Date).AddSeconds([Math]::Max($BootWaitSec, 150))
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 6
            $procs = (& $VMRUN @($auth + @("listProcessesInGuest",$Vmx)) 2>&1) -join "`n"
            if ($procs -match "explorer\.exe") { $sessionUp = $true; break }
        }
        if (-not $sessionUp) {
            throw "no desktop session (explorer.exe) after boot - enable AUTO-LOGIN in the CLEANBASELINE (netplwiz), then re-snapshot"
        }
        Write-Host "  desktop ready"

        $guestZip = Join-Path $GuestIntake $s.Name
        Write-Host "  copy sample into guest intake"
        VM ($auth + @("copyFileFromHostToGuest",$Vmx,$s.FullName,$guestZip)) | Out-Null

        Write-Host "  detonate (autohunt --once, isolated)"
        # Two guest quirks handled here:
        #  1. cmd.exe is blocked in this guest's automation session (a security
        #     policy makes runProgramInGuest cmd.exe return a generic exit 1);
        #     PowerShell works, so orchestrate through it.
        #  2. the VMware shared folder is not reliably reachable from that
        #     session, so autohunt writes to the GUEST-LOCAL runs dir and we
        #     package the review-queue drafts + copy them out (copyFileFromGuest
        #     ToHost is reliable) into $HostRunsDir where Autopilot reads them.
        $glog  = "C:\Users\Public\argus-autohunt.log"
        $gzip  = "C:\Users\Public\argus-review.zip"
        $gps   = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        $guestRuns = "$GuestRepo\runs"
        $psCmd = "`$env:ARGUS_RUNS='$guestRuns'; Set-Location '$GuestRepo'; " +
                 "python run.py autohunt --once *> '$glog'; " +
                 "Remove-Item '$gzip' -EA SilentlyContinue; " +
                 "if (Test-Path '$guestRuns\review_queue') { Compress-Archive -Path '$guestRuns\review_queue\*' -DestinationPath '$gzip' -Force -EA SilentlyContinue }; exit 0"
        & $VMRUN @($auth + @("runProgramInGuest",$Vmx,$gps,"-NoProfile","-ExecutionPolicy","Bypass","-Command",$psCmd)) 2>&1 | Out-Null
        # bring back the diagnostic log + the drafts package
        $hostLog = Join-Path $env:TEMP "argus-autohunt-guest.log"
        & $VMRUN @($auth + @("copyFileFromGuestToHost",$Vmx,$glog,$hostLog)) 2>&1 | Out-Null
        $hostZip = Join-Path $env:TEMP "argus-review.zip"
        Remove-Item $hostZip -EA SilentlyContinue
        & $VMRUN @($auth + @("copyFileFromGuestToHost",$Vmx,$gzip,$hostZip)) 2>&1 | Out-Null
        if (Test-Path $hostZip) {
            $rq = Join-Path $HostRunsDir "review_queue"
            New-Item -ItemType Directory -Force $rq | Out-Null
            Expand-Archive -Path $hostZip -DestinationPath $rq -Force
            $n = (Get-ChildItem $rq -Directory).Count
            Write-Host "  done -> drafts copied to host ($rq)" -ForegroundColor Green
        } else {
            Write-Host "  no draft produced (benign/inconclusive, or error) - log tail:" -ForegroundColor DarkYellow
            if (Test-Path $hostLog) { Get-Content $hostLog -Tail 18 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray } }
        }
    }
    catch {
        Write-Host "  ! $($s.Name): $($_.Exception.Message)" -ForegroundColor Red
    }
    finally {
        # always return to a clean snapshot before the next sample
        VMquiet ($base + @("revertToSnapshot",$Vmx,$Snapshot))
    }
}

# leave the VM at the clean baseline, powered off
VMquiet ($base + @("stop",$Vmx,"hard"))
Write-Host "`n== hunt-loop complete. Results in $ArgusRuns ==" -ForegroundColor Cyan
Write-Host "Review:  (on host) python run.py autohunt --reviews   / open the run folders"
