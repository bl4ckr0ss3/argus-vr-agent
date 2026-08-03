#requires -Version 5
<#
    ARGUS "sleep mode" — start the WHOLE machine with one command.

    Opens two windows:
      1. Web console + Autopilot  (serve.ps1)  — publishes >=85% findings to
         VirusTotal + 0xblack.dev automatically.
      2. The autonomous hunter    (autonomous.ps1) — fetches exotic samples from
         MalwareBazaar and detonates them in the VM, round after round, forever.

    Loads .env first so both windows inherit the API keys (MalwareBazaar for the
    hunter's preflight, VT/DeepSeek for the publisher). The VM is unencrypted now,
    so no -VmPassword is passed.

    ONE-LINER (from the repo root):
      .\scripts\night.ps1
#>
param(
    [string]$Vmx = "C:\Users\Ege\Documents\Virtual Machines\Windows 11 x64\Windows 11 x64.vmx"
)

$here = $PSScriptRoot
$repo = Split-Path $here -Parent

# Inherit .env into this process so both spawned windows get the keys.
$envFile = Join-Path $repo ".env"
if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        $l = $_.Trim()
        if ($l -and -not $l.StartsWith("#") -and $l.Contains("=")) {
            $i = $l.IndexOf("=")
            $k = $l.Substring(0, $i).Trim()
            $v = $l.Substring($i + 1).Trim().Trim('"')
            if ($k) { Set-Item -Path "Env:$k" -Value $v }
        }
    }
}

if (-not (Test-Path $Vmx)) { throw "VMX not found: $Vmx" }

Write-Host "== ARGUS sleep mode ==" -ForegroundColor Cyan
Write-Host "  starting web console + Autopilot ..." -ForegroundColor DarkGray
Start-Process powershell -ArgumentList @("-NoExit", "-ExecutionPolicy", "Bypass", "-NoProfile", "-Command", "& '$here\serve.ps1'")

Start-Sleep -Seconds 5   # let the server bind before the hunter starts feeding it

Write-Host "  starting the autonomous hunter ..." -ForegroundColor DarkGray
# No -VmPassword: the VM is unencrypted, and vmrun harmlessly ignores the default
# -vp on an unencrypted VM. (Passing -VmPassword '' mangled PowerShell arg parsing.)
Start-Process powershell -ArgumentList @("-NoExit", "-ExecutionPolicy", "Bypass", "-NoProfile", "-Command", "& '$here\autonomous.ps1' -Vmx '$Vmx'")

Write-Host ""
Write-Host "== ARGUS is running overnight. Sleep well. ==" -ForegroundColor Green
Write-Host "  dashboard : http://127.0.0.1:8765/pipeline"
Write-Host "  panel     : http://127.0.0.1:8765/panel"
Write-Host "  feed      : https://0xblack.dev/findings/"
Write-Host "  (two windows opened; Ctrl+C in each to stop)"
