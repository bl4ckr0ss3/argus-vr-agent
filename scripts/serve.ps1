#requires -Version 5
<#
    Terminal 1 launcher — the ARGUS web console (panel + Reverser + pipeline
    command center + Autopilot publisher).

    The whole point of this wrapper: pin ARGUS_RUNS to the SAME folder the hunter
    (autonomous.ps1 / hunt-loop.ps1) copies its drafts into. A plain
    `python run.py web` reads the repo-local runs\ dir, which stays EMPTY during a
    VM hunt (detonation happens in the guest; only drafts are copied to the host).
    That mismatch is why the panel + /pipeline looked "dead" — they were reading
    the wrong directory. With this, Terminal 1 and the hunter can't disagree.

    .env is loaded automatically by `run.py web`, so your VT / DeepSeek keys and
    ARGUS_ANALYST come along for publishing + the AI analyst.

    USAGE (Terminal 1, on the HOST):
      .\scripts\serve.ps1
      .\scripts\serve.ps1 -HostRunsDir C:\argus-results\runs -Port 8765
#>
param(
    [string]$HostRunsDir = "C:\argus-results\runs",   # MUST match the hunter's -HostRunsDir
    [int]   $Port        = 8765
)

$repoRoot = Split-Path -Parent $PSScriptRoot
$env:ARGUS_RUNS = $HostRunsDir
New-Item -ItemType Directory -Force (Join-Path $HostRunsDir "review_queue") | Out-Null

Write-Host "== ARGUS web console ==" -ForegroundColor Cyan
Write-Host "  ARGUS_RUNS : $HostRunsDir  (reading the hunter's drafts)" -ForegroundColor DarkGray
Write-Host "  panel      : http://127.0.0.1:$Port/panel"
Write-Host "  pipeline   : http://127.0.0.1:$Port/pipeline"
Write-Host "  reverser   : http://127.0.0.1:$Port/re"
Write-Host ""

& python (Join-Path $repoRoot "run.py") web --port $Port
