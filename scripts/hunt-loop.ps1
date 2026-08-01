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
    [string]$ArgusRuns  = "Z:\argus-results\runs",      # shared folder in the guest
    [int]$BootWaitSec   = 45,                            # seconds to let the guest + Tools come up
    [string]$Vmrun      = ""                             # auto-detected if blank
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
$auth  = @("-T", "ws", "-gu", $GuestUser, "-gp", $GuestPassword)

function VM([string[]]$vmArgs) { & $VMRUN @vmArgs }

$samples = Get-ChildItem -Path $SampleDir -Filter *.zip -File
if (-not $samples) { Write-Host "No .zip samples in $SampleDir"; exit 1 }
Write-Host "== ARGUS hunt-loop: $($samples.Count) sample(s) ==" -ForegroundColor Cyan

foreach ($s in $samples) {
    Write-Host "`n--- $($s.Name) ---" -ForegroundColor Yellow
    try {
        Write-Host "  revert -> $Snapshot"
        VM @("-T","ws","revertToSnapshot",$Vmx,$Snapshot) | Out-Null
        Write-Host "  start (headless)"
        VM @("-T","ws","start",$Vmx,"nogui") | Out-Null
        Start-Sleep -Seconds $BootWaitSec        # let the guest + VMware Tools come up

        $guestZip = Join-Path $GuestIntake $s.Name
        Write-Host "  copy sample into guest intake"
        VM ($auth + @("copyFileFromHostToGuest",$Vmx,$s.FullName,$guestZip)) | Out-Null

        Write-Host "  detonate (autohunt --once, isolated)"
        $cmd = "set ARGUS_RUNS=$ArgusRuns&& cd /d `"$GuestRepo`" && python run.py autohunt --once"
        VM ($auth + @("runProgramInGuest",$Vmx,"C:\Windows\System32\cmd.exe","/c",$cmd)) | Out-Null

        Write-Host "  done -> results on host ($ArgusRuns)" -ForegroundColor Green
    }
    catch {
        Write-Host "  ! $($s.Name): $($_.Exception.Message)" -ForegroundColor Red
    }
    finally {
        # always return to a clean snapshot before the next sample
        VM @("-T","ws","revertToSnapshot",$Vmx,$Snapshot) 2>$null | Out-Null
    }
}

# leave the VM at the clean baseline, powered off
VM @("-T","ws","stop",$Vmx,"hard") 2>$null | Out-Null
Write-Host "`n== hunt-loop complete. Results in $ArgusRuns ==" -ForegroundColor Cyan
Write-Host "Review:  (on host) python run.py autohunt --reviews   / open the run folders"
