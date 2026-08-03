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
    [int]$Port             = 8765
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
    Write-Host "  ! missing from env (your .env may not be exported to this shell):" -ForegroundColor Yellow
    foreach ($m in $missing) { Write-Host "      $m" -ForegroundColor Yellow }
    Write-Host "  Either export them, or set them in .env AND remove the guard in run.py loading." -ForegroundColor Yellow
    # .env is auto-loaded by run.py subprocesses, so only the preflight vars matter here.
}
if (-not $env:ARGUS_RUNS) { $env:ARGUS_RUNS = $HostRunsDir }
$env:ARGUS_AUTOPUBLISH = "1"

# ---- start PUBLISHER (web console + autopilot) in background ----
$pubLog  = Join-Path $LogDir "publisher.log"
$pubErr  = Join-Path $LogDir "publisher.err.log"
$env:ARGUS_RUNS = $HostRunsDir
Write-Host "  launching PUBLISHER (web :$Port / panel / pipeline, Autopilot ON) -> $pubLog" -ForegroundColor Green
$publisher = Start-Process -FilePath "pythonw" -ArgumentList @(
    (Join-Path $repoRoot "run.py"), "web", "--port", "$Port"
) -WorkingDirectory $repoRoot -RedirectStandardOutput $pubLog -RedirectStandardError $pubErr -WindowStyle Minimized -PassThru
Write-Host "    PID $($publisher.Id)  (log: $pubLog)" -ForegroundColor DarkGray

# ---- start HUNTER (fetch + VM detonation) in background ----
$hunLog  = Join-Path $LogDir "hunter.log"
$hunErr  = Join-Path $LogDir "hunter.err.log"
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
Write-Host "  launching HUNTER (MalwareBazaar fetch + VM detonation) -> $hunLog" -ForegroundColor Green
$hunter = Start-Process -FilePath "powershell" -ArgumentList @(
    "-NoProfile","-ExecutionPolicy","Bypass","-Command",$hunterCmd
) -WorkingDirectory $repoRoot -RedirectStandardOutput $hunLog -RedirectStandardError $hunErr -WindowStyle Minimized -PassThru
Write-Host "    PID $($hunter.Id)  (log: $hunLog)" -ForegroundColor DarkGray

# ---- tailing / monitoring loop ----
Write-Host ""
Write-Host "Both loops running. Ctrl+C to stop."
Write-Host "  panel    : http://127.0.0.1:$Port/panel"
Write-Host "  pipeline : http://127.0.0.1:$Port/pipeline"
Write-Host ""
try {
    while ($true) {
        Start-Sleep -Seconds 15
        $pubAlive = -not $publisher.HasExited
        $hunAlive = -not $hunter.HasExited
        Write-Host ("[{0:HH:mm:ss}] publisher={1} hunter={2}" -f (Get-Date),
                    $(if($pubAlive){'UP'}else{'DOWN'}), $(if($hunAlive){'UP'}else{'DOWN'})) -ForegroundColor DarkCyan
        if (-not $pubAlive) {
            Write-Host "  ! publisher exited; tail:" -ForegroundColor Yellow
            if (Test-Path $pubErr) { Get-Content $pubErr -Tail 5 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray } }
        }
        if (-not $hunAlive) {
            Write-Host "  ! hunter exited; tail:" -ForegroundColor Yellow
            if (Test-Path $hunErr) { Get-Content $hunErr -Tail 5 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray } }
        }
    }
}
finally {
    Write-Host "`nStopping ARGUS loops..."
    if (-not $publisher.HasExited) { Stop-Process -Id $publisher.Id -Force -ErrorAction SilentlyContinue }
    if (-not $hunter.HasExited)    { Stop-Process -Id $hunter.Id -Force -ErrorAction SilentlyContinue }
    Write-Host "Done."
}
