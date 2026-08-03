#requires -Version 5
<#
    ARGUS OVERNIGHT LOOP — start the whole autonomous pipeline and let it run.

    Two parallel processes:
      (1) PUBLISHER  — the web console + Autopilot daemon. Reads drafts from
                       $HostRunsDir and auto-publishes high-confidence findings
                       to VirusTotal + your static site (0xblack.dev).
      (2) HUNTER     — autonomous.ps1. Fetches malware families from MalwareBazaar
                       (this machine has internet), drives the VM through
                       hunt-loop.ps1 to detonate them, and copies the drafts back
                       to $HostRunsDir so the publisher can publish them.

    Run this ONCE, on the HOST (the machine with internet + the VMware VM).
    Both loops run forever until you Ctrl+C / stop the script.

    USAGE (as Administrator on the host):
      .\scripts\overnight.ps1 -Vmx "C:\...\ArgusVM.vmx" -GuestPassword 12345
      # optional speed:
      .\scripts\overnight.ps1 -Vmx ... -GuestPassword 12345 -Fast -Parallel 4

    REQUIREMENTS pre-set (in .env or env):
      MALWAREBAZAAR_API_KEY, VT_API_KEY, DEEPSEEK/OPENROUTER key,
      ARGUS_SITE_DIR, ARGUS_SITE_URL
#>
param(
    [Parameter(Mandatory)] [string]$Vmx,
    [string]$GuestUser     = "lab",
    [Parameter(Mandatory)] [string]$GuestPassword,
    [string]$VmPassword    = "",
    [string]$Snapshot      = "CLEANBASELINE",
    [int]$BatchSize        = 15,
    [int]$RoundDelaySec    = 240,
    [int]$Parallel         = 1,
    [switch]$Fast,
    [string]$HostRunsDir   = "C:\argus-results\runs",
    [string]$LogDir        = "C:\argus-results\logs",
    [int]$Port             = 8765,
    [int]$Hours            = 8,                    # 0 = run forever
    [int]$MaxRestarts      = 3,                    # restart crashed worker this many times
    [switch]$PreflightOnly                         # validate config then exit; no VM/sample execution
)
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
New-Item -ItemType Directory -Force $LogDir | Out-Null
New-Item -ItemType Directory -Force $HostRunsDir | Out-Null

# ---- load .env secrets into the environment --------------------------------
# .env is a KEY=VALUE file (with # comments). run.py auto-loads it for its OWN
# process, but the PowerShell subprocesses we spawn (autonomous.ps1 → fetch,
# publish) check $env:MALWAREBAZAAR_API_KEY etc. directly — so surface .env into
# this shell so children inherit it. Never echo the values.
$envFile = Join-Path $repoRoot ".env"
if (Test-Path $envFile) {
    foreach ($line in Get-Content $envFile) {
        $line = $line.Trim()
        if ($line -and -not $line.StartsWith("#") -and $line.Contains("=")) {
            $idx = $line.IndexOf("=")
            $k = $line.Substring(0, $idx).Trim()
            $v = $line.Substring($idx + 1).Trim().Trim('"')
            if ($k -and -not [Environment]::GetEnvironmentVariable($k)) { Set-Item -Path "Env:$k" -Value $v }
        }
    }
}

Write-Host "== ARGUS overnight loop ==" -ForegroundColor Cyan

# ---- preflight: required keys ----
$missing = @()
if (-not $env:MALWAREBAZAAR_API_KEY) { $missing += "MALWAREBAZAAR_API_KEY" }
if (-not $env:VT_API_KEY)            { $missing += "VT_API_KEY" }
if (-not $env:ARGUS_SITE_DIR)        { $missing += "ARGUS_SITE_DIR" }
if ($missing.Count) {
    throw "Missing required setting(s): $($missing -join ', '). Add them to .env before overnight mode."
}
if (-not (Test-Path -LiteralPath $Vmx)) { throw "VMX not found: $Vmx" }
if (-not (Test-Path -LiteralPath $env:ARGUS_SITE_DIR)) { throw "ARGUS_SITE_DIR not found: $env:ARGUS_SITE_DIR" }
if (-not $env:ARGUS_RUNS) { $env:ARGUS_RUNS = $HostRunsDir }
$env:ARGUS_AUTOPUBLISH = "1"
$deadline = if ($Hours -gt 0) { (Get-Date).AddHours($Hours) } else { $null }

if ($PreflightOnly) {
    $pythonCheck = (Get-Command python -ErrorAction Stop).Source
    Write-Host "  PRECHECK OK" -ForegroundColor Green
    Write-Host "    VMX        : $Vmx"
    Write-Host "    Python     : $pythonCheck"
    Write-Host "    Runs       : $HostRunsDir"
    Write-Host "    Site       : $env:ARGUS_SITE_DIR"
    Write-Host "    MB key     : SET"
    Write-Host "    VT key     : SET"
    Write-Host "    Autopublish: ON"
    Write-Host "    Duration   : $(if($Hours -gt 0){"$Hours hour(s)"}else{'forever'})"
    return
}

# ---- process launch helpers -------------------------------------------------
$python = (Get-Command python -ErrorAction Stop).Source
$env:ARGUS_RUNS = $HostRunsDir

# Build a single command string so paths with spaces serialize correctly through
# Start-Process -ArgumentList.
$bp = @(
    "& '{0}' -Vmx '{1}' -GuestUser '{2}' -GuestPassword '{3}'" -f `
        (Join-Path $PSScriptRoot "autonomous.ps1"), $Vmx, $GuestUser, $GuestPassword
)
$bp += "-Snapshot '{0}' -BatchSize {1} -RoundDelaySec {2} -HostRunsDir '{3}'" -f $Snapshot, $BatchSize, $RoundDelaySec, $HostRunsDir
if ($VmPassword) { $bp += "-VmPassword '{0}'" -f $VmPassword }
if ($Fast)       { $bp += "-Fast" }
if ($Parallel -gt 1) { $bp += "-Parallel $Parallel" }
$hunterCmd = $bp -join " "

$pubRestart = 0
$hunRestart = 0

function Start-Publisher([int]$attempt) {
    $out = Join-Path $LogDir ("publisher.{0}.log" -f $attempt)
    $err = Join-Path $LogDir ("publisher.{0}.err.log" -f $attempt)
    Write-Host "  launching PUBLISHER (attempt $attempt, web :$Port, Autopilot ON) -> $out" -ForegroundColor Green
    $p = Start-Process -FilePath $python -ArgumentList @(
        (Join-Path $repoRoot "run.py"), "web", "--port", "$Port"
    ) -WorkingDirectory $repoRoot -RedirectStandardOutput $out -RedirectStandardError $err -WindowStyle Minimized -PassThru
    return @{ process=$p; out=$out; err=$err }
}

function Start-Hunter([int]$attempt) {
    $out = Join-Path $LogDir ("hunter.{0}.log" -f $attempt)
    $err = Join-Path $LogDir ("hunter.{0}.err.log" -f $attempt)
    Write-Host "  launching HUNTER (attempt $attempt, MalwareBazaar + VM) -> $out" -ForegroundColor Green
    $p = Start-Process -FilePath "powershell" -ArgumentList @(
        "-NoProfile","-ExecutionPolicy","Bypass","-Command",$hunterCmd
    ) -WorkingDirectory $repoRoot -RedirectStandardOutput $out -RedirectStandardError $err -WindowStyle Minimized -PassThru
    return @{ process=$p; out=$out; err=$err }
}

$pubState = Start-Publisher $pubRestart
$hunState = Start-Hunter $hunRestart
$publisher = $pubState.process
$hunter = $hunState.process
Write-Host "    publisher PID $($publisher.Id); hunter PID $($hunter.Id)" -ForegroundColor DarkGray

# ---- tailing / monitoring loop ----
Write-Host ""
Write-Host "Both loops running. Ctrl+C to stop."
Write-Host "  panel    : http://127.0.0.1:$Port/panel"
Write-Host "  pipeline : http://127.0.0.1:$Port/pipeline"
Write-Host "  duration : $(if($Hours -gt 0){"$Hours hour(s)"}else{'until stopped'})"
Write-Host ""
try {
    while ($true) {
        Start-Sleep -Seconds 15
        if ($deadline -and (Get-Date) -ge $deadline) {
            Write-Host "Reached overnight duration ($Hours hour(s))." -ForegroundColor Cyan
            break
        }
        $pubAlive = -not $publisher.HasExited
        $hunAlive = -not $hunter.HasExited
        Write-Host ("[{0:HH:mm:ss}] publisher={1} hunter={2}" -f (Get-Date),
                    $(if($pubAlive){'UP'}else{'DOWN'}), $(if($hunAlive){'UP'}else{'DOWN'})) -ForegroundColor DarkCyan
        if (-not $pubAlive) {
            Write-Host "  ! publisher exited; tail:" -ForegroundColor Yellow
            if (Test-Path $pubState.err) { Get-Content $pubState.err -Tail 5 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray } }
            if ($pubRestart -lt $MaxRestarts) {
                $pubRestart++
                Start-Sleep -Seconds 5
                $pubState = Start-Publisher $pubRestart
                $publisher = $pubState.process
            } else { throw "publisher exceeded MaxRestarts=$MaxRestarts" }
        }
        if (-not $hunAlive) {
            Write-Host "  ! hunter exited; tail:" -ForegroundColor Yellow
            if (Test-Path $hunState.err) { Get-Content $hunState.err -Tail 5 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray } }
            if ($hunRestart -lt $MaxRestarts) {
                $hunRestart++
                Start-Sleep -Seconds 10
                $hunState = Start-Hunter $hunRestart
                $hunter = $hunState.process
            } else { throw "hunter exceeded MaxRestarts=$MaxRestarts" }
        }
    }
}
finally {
    Write-Host "`nStopping ARGUS loops..."
    if (-not $publisher.HasExited) { Stop-Process -Id $publisher.Id -Force -ErrorAction SilentlyContinue }
    if (-not $hunter.HasExited)    { Stop-Process -Id $hunter.Id -Force -ErrorAction SilentlyContinue }
    Write-Host "Done."
}
