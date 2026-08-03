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
    [int]$DetonateTimeout = 60,                          # per-sample detonation window; commodity stealers/loaders reveal C2+drops well inside 60s (raise if you hunt gated/beaconing families)
    [switch]$IsolateEach,                                # OFF = batch mode (default): one boot detonates ALL samples, one final revert. ON = old behaviour: per-sample revert+boot for full isolation.
    [int]$Parallel      = 3,                             # guest-side parallel detonations (batch mode only)
    [switch]$Fast,                                       # ARGUS_FAST=1: skip procmon/tshark/snapshots for max parallel throughput. REQUIRED if -Parallel > 1 (procmon is single-instance)
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

# Boot the guest and wait for an interactive desktop (explorer.exe). runProgram
# InGuest returns a generic 'exit 1' for every program until a user is logged in,
# so the baseline MUST auto-login; we poll rather than fixed-sleep so a fast boot
# proceeds immediately and only a genuine failure burns the full timeout.
function Wait-Desktop {
    $running = ((& $VMRUN @($base + @("list")) 2>&1) -join "`n") -match [regex]::Escape($Vmx)
    if (-not $running) { VMquiet ($base + @("start",$Vmx,"nogui")) }
    $deadline = (Get-Date).AddSeconds([Math]::Max($BootWaitSec, 240))
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 6
        $procs = (& $VMRUN @($auth + @("listProcessesInGuest",$Vmx)) 2>&1) -join "`n"
        if ($procs -match "explorer\.exe") { return $true }
    }
    return $false
}

$samples = Get-ChildItem -Path $SampleDir -Filter *.zip -File
if (-not $samples) { Write-Host "No .zip samples in $SampleDir"; exit 1 }
# procmon is a single-instance global tool — parallel detonations would corrupt
# each other's capture. Guard against silent misconfiguration.
if ($Parallel -gt 1 -and -not $Fast) {
    Write-Host "WARNING: -Parallel $Parallel without -Fast (procmon is single-instance; " -ForegroundColor Yellow
    Write-Host "         parallel runs would corrupt each other's telemetry)." -ForegroundColor Yellow
    Write-Host "         Falling back to serial batch (safer). Use  -Fast -Parallel N  for max throughput." -ForegroundColor Yellow
    $Parallel = 1
}
Write-Host "== ARGUS hunt-loop: $($samples.Count) sample(s), mode=$([string](if($IsolateEach){'isolated per-sample'}else{"batch (parallel=$Parallel" + $(if($Fast){', FAST'}else{''}) + ')'})) ==" -ForegroundColor Cyan

$batchStart = Get-Date

function Invoke-GuestAutohunt {
    # run autohunt once in the guest; package drafts; copy back. Outputs:
    #   $global:gLogText (tail)  $global:hasDraft (bool)
    $glog  = "C:\Users\Public\argus-autohunt.log"
    $gzip  = "C:\Users\Public\argus-review.zip"
    $gps   = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    $guestRuns = "$GuestRepo\runs"
    # batch mode: drain the WHOLE intake queue with parallel detonations. We set
    # ARGUS_PROFILE=production so each detonation is capped at $DetonateTimeout and
    # ARGUS_PARALLEL enables concurrent detonations inside the guest.
    $envStr = "`$env:ARGUS_RUNS='$guestRuns'; `$env:ARGUS_PROFILE='production'; `$env:ARGUS_PARALLEL='$Parallel'; "
    if ($Fast) { $envStr += "`$env:ARGUS_FAST='1'; " }
    if (-not $IsolateEach) { $envStr += "`$env:ARGUS_DETONATE_MAX='$DetonateTimeout'; " }
    $psCmd = $envStr +
             "Set-Location '$GuestRepo'; " +
             "python run.py autohunt --once --timeout $DetonateTimeout *> '$glog'; " +
             "Remove-Item '$gzip' -EA SilentlyContinue; " +
             "if (Test-Path '$guestRuns\review_queue') { Compress-Archive -Path '$guestRuns\review_queue\*' -DestinationPath '$gzip' -Force -EA SilentlyContinue }; exit 0"
    & $VMRUN @($auth + @("runProgramInGuest",$Vmx,$gps,"-NoProfile","-ExecutionPolicy","Bypass","-Command",$psCmd)) 2>&1 | Out-Null

    $hostLog = Join-Path $env:TEMP "argus-autohunt-guest.log"
    & $VMRUN @($auth + @("copyFileFromGuestToHost",$Vmx,$glog,$hostLog)) 2>&1 | Out-Null
    $global:gLogText = if (Test-Path $hostLog) { Get-Content $hostLog -Raw -EA SilentlyContinue } else { "" }

    $hostZip = Join-Path $env:TEMP "argus-review.zip"
    Remove-Item $hostZip -EA SilentlyContinue
    & $VMRUN @($auth + @("copyFileFromGuestToHost",$Vmx,$gzip,$hostZip)) 2>&1 | Out-Null
    $global:hasDraft = Test-Path $hostZip
    if ($global:hasDraft) {
        $rq = Join-Path $HostRunsDir "review_queue"
        New-Item -ItemType Directory -Force $rq | Out-Null
        Expand-Archive -Path $hostZip -DestinationPath $rq -Force
    }
}

if ($IsolateEach) {
    # ---- per-sample isolation (one revert+boot per sample) ----
    foreach ($s in $samples) {
        Write-Host "`n--- $($s.Name) ---" -ForegroundColor Yellow
        $t0 = Get-Date; $tReverted = $t0; $tReady = $t0; $tDeton = $t0
        try {
            Write-Host "  revert -> $Snapshot"
            VM ($base + @("revertToSnapshot",$Vmx,$Snapshot)) | Out-Null
            $tReverted = Get-Date
            Write-Host "  start (headless)"
            Write-Host "  waiting for desktop session (auto-login)..."
            if (-not (Wait-Desktop)) {
                Write-Host "  desktop not up - reverting + retrying once" -ForegroundColor DarkYellow
                VM ($base + @("revertToSnapshot",$Vmx,$Snapshot)) | Out-Null
                if (-not (Wait-Desktop)) {
                    throw "no desktop session (explorer.exe) after 2 boots - if this is EVERY sample, enable AUTO-LOGIN in CLEANBASELINE (netplwiz) + re-snapshot"
                }
            }
            Write-Host "  desktop ready"; $tReady = Get-Date

            $guestZip = Join-Path $GuestIntake $s.Name
            Write-Host "  copy sample into guest intake"
            VM ($auth + @("copyFileFromHostToGuest",$Vmx,$s.FullName,$guestZip)) | Out-Null

            Write-Host "  detonate (autohunt --once, isolated)"
            $tDeton = Get-Date
            Invoke-GuestAutohunt
            if ($global:hasDraft) {
                $n = (Get-ChildItem (Join-Path $HostRunsDir "review_queue") -Directory -EA SilentlyContinue).Count
                Write-Host "  done -> drafts copied to host ($HostRunsDir\review_queue)" -ForegroundColor Green
            } else {
                Write-Host "  no draft produced (benign/inconclusive) - log tail:" -ForegroundColor DarkYellow
                if ($global:gLogText) { ($global:gLogText -split "`n" | Select-Object -Last 18) | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray } }
            }
        }
        catch { Write-Host "  ! $($s.Name): $($_.Exception.Message)" -ForegroundColor Red }
        $now = Get-Date
        $rev = [int]($tReverted - $t0).TotalSeconds
        $res = [int]($tReady - $tReverted).TotalSeconds
        $det = [int]($tDeton - $tReady).TotalSeconds
        $cpy = [int]($now - $tDeton).TotalSeconds
        $tot = [int]($now - $t0).TotalSeconds
        Write-Host ("  [timing] revert ${rev}s | resume-wait ${res}s | detonate ${det}s | copyout ${cpy}s | TOTAL ${tot}s") -ForegroundColor DarkCyan
    }
} else {
    # ---- batch mode: one boot, all samples, one final revert ----
    $t0 = Get-Date
    Write-Host "`n--- BATCH: $($samples.Count) sample(s), single boot + parallel detonation ---" -ForegroundColor Yellow
    try {
        Write-Host "  revert -> $Snapshot"
        VM ($base + @("revertToSnapshot",$Vmx,$Snapshot)) | Out-Null
        Write-Host "  start (headless) + wait for desktop..."
        if (-not (Wait-Desktop)) {
            Write-Host "  desktop not up - reverting + retrying once" -ForegroundColor DarkYellow
            VM ($base + @("revertToSnapshot",$Vmx,$Snapshot)) | Out-Null
            if (-not (Wait-Desktop)) { throw "no desktop session after 2 boots" }
        }
        Write-Host "  desktop ready"

        Write-Host "  copy $($samples.Count) sample(s) into guest intake"
        foreach ($s in $samples) {
            VMquiet ($auth + @("copyFileFromHostToGuest",$Vmx,$s.FullName,(Join-Path $GuestIntake $s.Name)))
        }

        Write-Host "  detonate batch (autohunt --once, parallel=$Parallel, timeout=$DetonateTimeout s/sample)"
        Invoke-GuestAutohunt

        if ($global:hasDraft) {
            $n = (Get-ChildItem (Join-Path $HostRunsDir "review_queue") -Directory -EA SilentlyContinue).Count
            Write-Host "  done -> $n draft(s) copied to host ($HostRunsDir\review_queue)" -ForegroundColor Green
        } else {
            Write-Host "  no drafts produced - log tail:" -ForegroundColor DarkYellow
            if ($global:gLogText) { ($global:gLogText -split "`n" | Select-Object -Last 20) | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray } }
        }
    }
    catch { Write-Host "  ! BATCH: $($_.Exception.Message)" -ForegroundColor Red }
    $now = Get-Date
    $tot = [int]($now - $t0).TotalSeconds
    Write-Host ("  [timing] BATCH TOTAL ${tot}s for $($samples.Count) sample(s) = ~$([int]($tot / $samples.Count))s/sample (vs ~376s/sample isolated)") -ForegroundColor DarkCyan
}

# Leave the VM AT the clean snapshot. Do NOT hard-stop: a hard power-off right
# after reverting orphans the current-state delta disk and corrupts the chain.
# A single revert here wipes the last sample's malware; the next run reverts again.
VMquiet ($base + @("revertToSnapshot",$Vmx,$Snapshot))
$batchSecs = [int]((Get-Date) - $batchStart).TotalSeconds
$perSample = if ($samples.Count) { [int]($batchSecs / $samples.Count) } else { 0 }
Write-Host "`n== hunt-loop complete: $($samples.Count) sample(s) in ${batchSecs}s (~${perSample}s each). Drafts -> $HostRunsDir ==" -ForegroundColor Cyan
Write-Host "Review/publish on the host: http://127.0.0.1:8765/panel"
