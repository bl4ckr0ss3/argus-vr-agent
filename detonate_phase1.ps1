# detonate_phase1.ps1 — one-shot Phase 1 detonation (RUN INSIDE THE VM ONLY).
#
# Does the whole prep + detonation:
#   1. strips API credentials so ARGUS's guard passes (detonate needs no key)
#   2. puts tshark on PATH, checks procmon resolves
#   3. reminds you FakeNet must be running
#   4. runs the detonation with C2 answered (Phase 1)
#
# Usage (Admin PowerShell, FakeNet already running in its own window):
#   .\detonate_phase1.ps1
#   .\detonate_phase1.ps1 -Sample "C:\Users\lab\Downloads\hyper-grid-windows-x64.exe" -Timeout 300
param(
    [string]$Sample   = "C:\Users\lab\Downloads\hyper-grid-windows-x64.exe",
    [string]$ArgusDir = "C:\argus-vr-agent",
    [int]   $Timeout  = 300,
    [string]$Wireshark = "C:\Program Files\Wireshark"
)

$ErrorActionPreference = "Stop"
Write-Host "=== ARGUS Phase 1 detonation ===" -ForegroundColor Cyan

# --- sanity: this must be a VM ---------------------------------------------
if (-not (Test-Path $Sample))   { Write-Host "!! Sample not found: $Sample" -ForegroundColor Red; exit 1 }
if (-not (Test-Path $ArgusDir)) { Write-Host "!! ARGUS dir not found: $ArgusDir" -ForegroundColor Red; exit 1 }
Set-Location $ArgusDir

# --- 1. strip credentials (the guard blocks detonation otherwise) ----------
if (Test-Path ".\.env") {
    Move-Item ".\.env" ".\.env.bak" -Force
    Write-Host "[cred] .env -> .env.bak (moved out of the way)" -ForegroundColor Yellow
} else {
    Write-Host "[cred] no .env present — good" -ForegroundColor Green
}
foreach ($k in "OPENROUTER_API_KEY","DEEPSEEK_API_KEY","ARGUS_API_KEY","ANTHROPIC_API_KEY",
                "OPENAI_API_KEY","MOONSHOT_API_KEY","KIMI_API_KEY","GLM_API_KEY",
                "ZHIPU_API_KEY","AGENTROUTER_API_KEY","TOKENROUTER_API_KEY") {
    if (Test-Path "Env:$k") { Remove-Item "Env:$k"; Write-Host "[cred] unset $k" -ForegroundColor Yellow }
}

# --- 2. tools on PATH ------------------------------------------------------
if (Test-Path $Wireshark) { $env:PATH += ";$Wireshark" }
$tshark  = (Get-Command tshark  -ErrorAction SilentlyContinue)
$procmon = (Get-Command procmon -ErrorAction SilentlyContinue)
if (-not $procmon -and (Test-Path "C:\Tools\Procmon64.exe")) { $env:ARGUS_PROCMON = "C:\Tools\Procmon64.exe"; $procmon = $true }
Write-Host ("[tool] tshark:  " + $(if ($tshark)  {"OK"} else {"MISSING (install Wireshark) — no pcap"})) -ForegroundColor $(if($tshark){"Green"}else{"Red"})
Write-Host ("[tool] procmon: " + $(if ($procmon) {"OK"} else {"MISSING (put Procmon64.exe in C:\Tools) — no behavior log"})) -ForegroundColor $(if($procmon){"Green"}else{"Red"})

# --- 3. FakeNet reminder ---------------------------------------------------
Write-Host "[net] Confirm FakeNet-NG is RUNNING in its own window (fakes the C2). Host-only network." -ForegroundColor Cyan
$env:ARGUS_FAKENET = ""   # you started FakeNet yourself; don't auto-launch

# --- 4. detonate -----------------------------------------------------------
Write-Host "[run] detonating (timeout ${Timeout}s)…" -ForegroundColor Cyan
python run.py detonate "$Sample" --timeout $Timeout

Write-Host "=== done — the output folder is printed above (runs\dynamic\...) ===" -ForegroundColor Cyan
