#requires -Version 5
<#
    ARGUS analysis-VM setup - run ONCE, then snapshot the VM as 'clean-baseline'.

    Fixes the friction this session kept hitting:
      * tools not on PATH (tshark / procmon) - added idempotently, correctly
        semicolon-separated (no more glued-together corrupted PATH)
      * script execution blocked - sets RemoteSigned for the current user
      * Procmon EULA dialog hanging headless captures - pre-accepts it
      * API keys accidentally left in the detonation VM - checks and warns,
        because 'detonate' refuses to run while credentials are present

    Usage (an elevated shell is recommended, for Procmon / FakeNet):
        Set-ExecutionPolicy -Scope Process Bypass -Force
        .\scripts\vm-setup.ps1
        # confirm tools resolve, then snapshot the VM as 'clean-baseline'

    Per-sample workflow after this:
        revert clean-baseline  ->  git pull  ->  python run.py detonate SAMPLE

    NOTE: keep this file ASCII-only. Windows PowerShell 5.1 reads a no-BOM
    script as Windows-1252, so a stray em-dash or smart-quote decodes into a
    character it treats as a string terminator and the whole script fails to parse.
#>
param(
    [string]$WiresharkDir    = "C:\Program Files\Wireshark",
    [string]$SysinternalsDir = "C:\Tools\Sysinternals",
    [string]$FakeNetDir      = ""    # optional, e.g. C:\Tools\fakenet-ng
)

$ErrorActionPreference = "Stop"

function Add-ToUserPath([string[]]$dirs) {
    # Idempotent, always ';'-separated. Rebuilds cleanly so a previously
    # corrupted (glued) PATH gets normalised instead of appended to.
    $cur   = [Environment]::GetEnvironmentVariable("Path", "User")
    $parts = @($cur -split ';' | Where-Object { $_ -ne '' })
    foreach ($d in $dirs) {
        if ($d -and (Test-Path $d) -and ($parts -notcontains $d)) { $parts += $d }
    }
    $new = ($parts -join ';')
    [Environment]::SetEnvironmentVariable("Path", $new, "User")
    $env:Path = "$new;" + [Environment]::GetEnvironmentVariable("Path", "Machine")
}

Write-Host "== ARGUS VM setup ==" -ForegroundColor Cyan

# 1. tools on PATH
$dirs = @($WiresharkDir, $SysinternalsDir)
if ($FakeNetDir) { $dirs += $FakeNetDir }
Add-ToUserPath $dirs

# 2. allow locally-authored scripts (this one, and the sync helper)
try { Set-ExecutionPolicy -Scope CurrentUser RemoteSigned -Force } catch {}

# 3. pre-accept the Procmon EULA so headless /BackingFile captures don't stall
if (Get-Command procmon -ErrorAction SilentlyContinue) {
    Start-Process procmon -ArgumentList "/AcceptEula", "/Terminate" -Wait -ErrorAction SilentlyContinue
}

# 4. verify the two tools the detonation pipeline needs
Write-Host "`n-- tool resolution --"
$missing = $false
foreach ($t in "tshark", "procmon") {
    $p = (Get-Command $t -ErrorAction SilentlyContinue).Source
    if ($p) {
        Write-Host ("  OK  {0,-8} -> {1}" -f $t, $p) -ForegroundColor Green
    } else {
        $hint = if ($t -eq "tshark") { "-WiresharkDir <path>" } else { "-SysinternalsDir <path>" }
        Write-Host ("  !!  {0,-8} NOT FOUND - pass {1}" -f $t, $hint) -ForegroundColor Yellow
        $missing = $true
    }
}

# 5. credential-safety invariant: this VM must hold NO API keys
$keys = @("OPENROUTER_API_KEY","DEEPSEEK_API_KEY","ANTHROPIC_API_KEY","OPENAI_API_KEY",
          "GLM_API_KEY","ZHIPU_API_KEY","MOONSHOT_API_KEY","KIMI_API_KEY",
          "AGENTROUTER_API_KEY","TOKENROUTER_API_KEY","ARGUS_API_KEY")
$present = @()
foreach ($k in $keys) { if ([Environment]::GetEnvironmentVariable($k)) { $present += $k } }
if (Test-Path ".\.env") { $present += ".env file" }
if ($present.Count) {
    Write-Host "`n  DANGER  credentials present in this VM: $($present -join ', ')" -ForegroundColor Red
    Write-Host "          detonate will BLOCK. Remove them BEFORE snapshotting." -ForegroundColor Red
} else {
    Write-Host "`n  OK  no API credentials in this VM (detonation-safe)." -ForegroundColor Green
}

Write-Host "`nNext: confirm the tools above resolve, then snapshot this VM as 'clean-baseline'." -ForegroundColor Cyan
Write-Host "Per-sample: revert clean-baseline -> git pull -> python run.py detonate SAMPLE"
