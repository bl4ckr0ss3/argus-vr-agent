#requires -Version 5
<#
    Update the CLEANBASELINE snapshot with the latest ARGUS code — WITHOUT giving
    the guest internet and WITHOUT ever copying host credentials into it.

    Why this exists: autohunt + the detonation engine run INSIDE the guest, so the
    guest's copy of the code is what actually detonates samples. That copy is frozen
    in the CLEANBASELINE snapshot. `git pull` can't run in the guest (it's Host-only
    / offline by design), so instead we build a code-ONLY zip on the host (explicit
    allow-list — no .env, no runs/, no secrets), copy it in over vmrun, extract it
    over C:\argus-vr-agent, sanity-check the import, then re-take the snapshot.

    SAFE with encrypted VMs: uses -vp for the encryption password, a GRACEFUL guest
    shutdown before any snapshot op (never a hard stop on a running snapshot — that
    is what corrupted the disk chain last time), then deletes + recreates the
    powered-off CLEANBASELINE.

    USAGE (HOST) — same params you already pass to autonomous.ps1:
      .\scripts\update-baseline.ps1 `
          -Vmx "C:\Users\Ege\Documents\Virtual Machines\Windows 11 x64\Windows 11 x64.vmx" `
          -VmPassword 12345678 -GuestUser researcher -GuestPassword 12345
#>
param(
    [Parameter(Mandatory)] [string]$Vmx,
    [string]$Snapshot   = "CLEANBASELINE",
    [Parameter(Mandatory)] [string]$GuestUser,
    [Parameter(Mandatory)] [string]$GuestPassword,
    [string]$GuestRepo  = "C:\argus-vr-agent",
    [string]$VmPassword = "",
    [string]$Vmrun      = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot

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

if (-not (Test-Path $Vmx)) { throw "VMX not found: $Vmx  (pass the real .vmx path, not <vmx>)" }
$VMRUN = Find-Vmrun
$base  = @("-T", "ws"); if ($VmPassword) { $base += @("-vp", $VmPassword) }
$auth  = $base + @("-gu", $GuestUser, "-gp", $GuestPassword)

function VM([string[]]$a)      { $o = & $VMRUN @a 2>&1; if ($LASTEXITCODE -ne 0) { throw ("vmrun failed: " + ($o -join ' ')) }; $o }
function VMquiet([string[]]$a) { & $VMRUN @a 2>&1 | Out-Null }
function VMtry([string[]]$a)   { & $VMRUN @a 2>&1 | Out-Null }   # non-fatal

Write-Host "== ARGUS baseline updater ==" -ForegroundColor Cyan

# --- 1. Build a code-ONLY zip on the host (allow-list; no .env / secrets) -------
$stage = Join-Path $env:TEMP "argus-baseline-update.zip"
Remove-Item $stage -ErrorAction SilentlyContinue
$include = @("argus","web","scripts","run.py","config.py","requirements.txt") |
    ForEach-Object { Join-Path $repoRoot $_ } | Where-Object { Test-Path $_ }
if (-not $include) { throw "no code found under $repoRoot" }
Write-Host "  packing (no .env, no runs/): $([IO.Path]::GetFileName($stage))"
Compress-Archive -Path $include -DestinationPath $stage -Force
if ((Get-ChildItem $stage).Length -lt 1000) { throw "staged zip looks empty" }

# --- 2. Revert + boot the baseline ---------------------------------------------
Write-Host "  revert -> $Snapshot" -ForegroundColor Yellow
VM ($base + @("revertToSnapshot",$Vmx,$Snapshot)) | Out-Null
$running = ((& $VMRUN @($base + @("list")) 2>&1) -join "`n") -match [regex]::Escape($Vmx)
if (-not $running) { VMquiet ($base + @("start",$Vmx,"nogui")) }
Write-Host "  waiting for desktop session (auto-login)..."
$deadline = (Get-Date).AddSeconds(240); $up = $false
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 6
    if (((& $VMRUN @($auth + @("listProcessesInGuest",$Vmx)) 2>&1) -join "`n") -match "explorer\.exe") { $up = $true; break }
}
if (-not $up) { throw "no desktop session after boot - enable auto-login in the baseline first" }
Write-Host "  desktop ready" -ForegroundColor Green

# --- 3. Copy the zip in and extract it over the guest repo ----------------------
$guestZip = "C:\Users\Public\argus-update.zip"
Write-Host "  copying code into guest + extracting"
VM ($auth + @("copyFileFromHostToGuest",$Vmx,$stage,$guestZip)) | Out-Null
$gps = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
$log = "C:\Users\Public\argus-update.log"
# Verify by grepping the EXTRACTED files for the new code markers (Select-String,
# not `python -c`): no dependency on python/imports in the guest, and — critically —
# no nested double-quotes, which don't survive vmrun's argument passing.
$ps  = "Expand-Archive -Path '$guestZip' -DestinationPath '$GuestRepo' -Force; " +
       "`$a = Select-String -Path '$GuestRepo\argus\autohunt.py' -Pattern '_extract_with_7z' -Quiet -EA SilentlyContinue; " +
       "`$b = Select-String -Path '$GuestRepo\argus\tools\dynamic.py' -Pattern '_SETTLE_SECONDS' -Quiet -EA SilentlyContinue; " +
       "('recursive-unpack: ' + `$a) | Out-File -FilePath '$log' -Encoding ascii; " +
       "('settle-window: '   + `$b) | Out-File -FilePath '$log' -Append -Encoding ascii; exit 0"
& $VMRUN @($auth + @("runProgramInGuest",$Vmx,$gps,"-NoProfile","-ExecutionPolicy","Bypass","-Command",$ps)) 2>&1 | Out-Null

# bring the verification log back to the host and show it
$hostLog = Join-Path $env:TEMP "argus-update-guest.log"
Remove-Item $hostLog -ErrorAction SilentlyContinue
VMtry ($auth + @("copyFileFromGuestToHost",$Vmx,$log,$hostLog))
$verified = $false
if (Test-Path $hostLog) {
    $txt = Get-Content $hostLog -Raw
    Write-Host "  guest verification:" -ForegroundColor DarkGray
    $txt -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
    if ($txt -match "recursive-unpack:\s*True" -and $txt -match "settle-window:\s*True") { $verified = $true }
} else {
    Write-Host "  (no verification log came back from the guest — extract or copy-out failed)" -ForegroundColor DarkYellow
}
if (-not $verified) {
    throw "guest did not verify the new code (import check failed). NOT re-snapshotting - your existing CLEANBASELINE is untouched."
}
Write-Host "  new code verified in guest" -ForegroundColor Green

# --- 4. Graceful shutdown (never hard-stop a running snapshot) ------------------
Write-Host "  shutting the guest down cleanly..."
VMtry ($base + @("stop",$Vmx,"soft"))
$off = $false; $deadline = (Get-Date).AddSeconds(180)
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 4
    if (-not (((& $VMRUN @($base + @("list")) 2>&1) -join "`n") -match [regex]::Escape($Vmx))) { $off = $true; break }
}
if (-not $off) { throw "guest did not power off within 180s - re-snapshot manually once it is off (do NOT hard-stop)" }
Write-Host "  powered off" -ForegroundColor Green

# --- 5. Replace the CLEANBASELINE snapshot (powered-off) ------------------------
Write-Host "  re-taking snapshot '$Snapshot'"
VMtry ($base + @("deleteSnapshot",$Vmx,$Snapshot))   # non-fatal if it was already gone
VM  ($base + @("snapshot",$Vmx,$Snapshot)) | Out-Null

Write-Host "`n== baseline updated: '$Snapshot' now has recursive-unpack + settle-window + latest autohunt ==" -ForegroundColor Cyan
Write-Host "Run your hunt again:" -ForegroundColor Cyan
Write-Host "  .\scripts\autonomous.ps1 -Vmx `"$Vmx`" -VmPassword $VmPassword -GuestUser $GuestUser -GuestPassword $GuestPassword -HostRunsDir C:\argus-results\runs"
Write-Host "`nTip: for .rar samples, put 7z.exe in C:\Tools INSIDE the guest before running this, so it's baked into the snapshot." -ForegroundColor DarkGray
