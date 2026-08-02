#requires -Version 5
<#
    ARGUS fully-autonomous hunt driver (host side).

    The continuous outer loop that keeps the machine fed: each round it fetches a
    fresh batch of samples from MalwareBazaar (the HOST has internet; the guest
    never does), then drives the encrypted VM through hunt-loop.ps1 to detonate
    them one-by-one with a clean revert between each. Verdicts land on the shared
    folder; the always-on web server's Autopilot publishes the >=85% ones to
    VirusTotal + the site. Nothing here talks to the internet from the guest.

    Run this ALONGSIDE the web server (which does the publishing):
       Terminal 1:  python run.py web           (with ARGUS_AUTOPUBLISH=1 + site env)
       Terminal 2:  scripts\autonomous.ps1 ...   (this - feeds the VM)

    PREREQUISITES (verified at startup):
      * vmrun.exe present; the .vmx path is correct
      * MALWAREBAZAAR_API_KEY set (host, for fetch)
      * VMware Tools running in the guest
      * a CLEANBASELINE snapshot that has: latest argus code, tools on PATH,
        NO LLM credentials, Host-only networking, ARGUS_RUNS -> shared folder
#>
param(
    [Parameter(Mandatory)] [string]$Vmx,
    [string]$GuestUser     = "lab",
    [string]$GuestPassword = "12345",
    [string]$VmPassword    = "12345678",           # VM encryption password
    [string]$Snapshot      = "CLEANBASELINE",
    [string[]]$Tags        = @("AsyncRAT","RedLineStealer","Formbook","AgentTesla",
                               "XWorm","Amadey","Stealc","Lumma","Remcos","njrat"),
    [int]$BatchSize        = 12,
    [int]$RoundDelaySec    = 300,                   # pause between rounds
    [int]$MaxRounds        = 0,                     # 0 = forever
    [string]$BatchDir      = "C:\argus-hunt\batch",
    # Where the GUEST writes results so they reach the host (shared folder).
    # UNC form is the most reliable across the runProgramInGuest session; must
    # resolve to host C:\argus-results\runs (what the web Autopilot reads).
    [string]$GuestArgusRuns= "\\vmware-host\Shared Folders\argus-results\runs",
    [string]$Vmrun         = ""
)
$ErrorActionPreference = "Stop"

function Find-Vmrun {
    if ($Vmrun -and (Test-Path $Vmrun)) { return $Vmrun }
    foreach ($p in @(
        "C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe",
        "C:\Program Files\VMware\VMware Workstation\vmrun.exe",
        "C:\Program Files (x86)\VMware\VMware Player\vmrun.exe")) {
        if (Test-Path $p) { return $p }
    }
    $g = (Get-Command vmrun -ErrorAction SilentlyContinue).Source
    if ($g) { return $g }
    throw "vmrun.exe not found - pass -Vmrun <path>"
}

# ---- preflight ----------------------------------------------------------
Write-Host "== ARGUS autonomous driver - preflight ==" -ForegroundColor Cyan
$VMRUN = Find-Vmrun
$base  = @("-T","ws"); if ($VmPassword) { $base += @("-vp",$VmPassword) }

if (-not (Test-Path $Vmx)) { throw "VMX not found: $Vmx" }
if (-not $env:MALWAREBAZAAR_API_KEY) { throw "MALWAREBAZAAR_API_KEY not set (needed for fetch)" }

Write-Host "  vmrun: $VMRUN"
Write-Host "  checking snapshots..."
$snaps = & $VMRUN @base listSnapshots $Vmx 2>&1
if ($LASTEXITCODE -ne 0) { throw "vmrun/listSnapshots failed (wrong -VmPassword?): $snaps" }
if ($snaps -notmatch [regex]::Escape($Snapshot)) {
    throw "Snapshot '$Snapshot' not found. Snapshots: $snaps"
}
Write-Host "  snapshot '$Snapshot' present" -ForegroundColor Green
Write-Host "  encryption password accepted; guest '$GuestUser'" -ForegroundColor Green

$repoRoot = Split-Path $PSScriptRoot -Parent
$huntLoop = Join-Path $PSScriptRoot "hunt-loop.ps1"
if (-not (Test-Path $huntLoop)) { throw "hunt-loop.ps1 not next to this script" }

# ---- main loop ----------------------------------------------------------
$round = 0
while ($true) {
    $round++
    $tag = $Tags[($round - 1) % $Tags.Count]
    Write-Host "`n===== ROUND $round  (family: $tag) =====" -ForegroundColor Cyan

    # fresh batch dir each round so we never re-detonate old samples
    if (Test-Path $BatchDir) { Remove-Item "$BatchDir\*" -Force -Recurse -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Force $BatchDir | Out-Null

    Write-Host "  fetching up to $BatchSize '$tag' samples..."
    $env:ARGUS_INTAKE = $BatchDir
    & python (Join-Path $repoRoot "run.py") fetch --tag $tag --limit $BatchSize 2>&1 | Write-Host

    $zips = @(Get-ChildItem -Path $BatchDir -Filter *.zip -File -ErrorAction SilentlyContinue)
    if ($zips.Count -eq 0) {
        Write-Host "  no samples this round (family embargoed/empty) - next family" -ForegroundColor DarkYellow
    } else {
        Write-Host "  detonating $($zips.Count) sample(s) through the VM..." -ForegroundColor Yellow
        & $huntLoop -Vmx $Vmx -Snapshot $Snapshot -SampleDir $BatchDir `
            -GuestUser $GuestUser -GuestPassword $GuestPassword -VmPassword $VmPassword `
            -ArgusRuns $GuestArgusRuns
        Write-Host "  round $round done - Autopilot will publish the strong findings" -ForegroundColor Green
    }

    if ($MaxRounds -gt 0 -and $round -ge $MaxRounds) {
        Write-Host "`n== reached MaxRounds ($MaxRounds), stopping ==" -ForegroundColor Cyan
        break
    }
    Write-Host "  sleeping $RoundDelaySec s before next round (Ctrl+C to stop)..."
    Start-Sleep -Seconds $RoundDelaySec
}
