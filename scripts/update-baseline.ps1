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
    [string]$Vmrun      = "",
    [switch]$With7z,                                    # also copy host 7-Zip into guest C:\Tools (unlocks .rar samples)
    [switch]$Suspend                                    # snapshot a SUSPENDED (RAM) state -> hunts resume in seconds, no boot
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

# --- 2. Revert to the baseline, OR create it from the current VM state ----------
# If CLEANBASELINE doesn't exist (e.g. you just deleted it to change the VM's RAM),
# skip the revert and snapshot whatever is currently booted instead of failing.
$snapList = (& $VMRUN @($base + @("listSnapshots",$Vmx)) 2>&1) -join "`n"
if ($snapList -match [regex]::Escape($Snapshot)) {
    Write-Host "  revert -> $Snapshot" -ForegroundColor Yellow
    VM ($base + @("revertToSnapshot",$Vmx,$Snapshot)) | Out-Null
} else {
    Write-Host "  '$Snapshot' not found — creating it from the current VM state" -ForegroundColor Yellow
}
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

# --- 3b. Optional: bake 7-Zip into the guest for .rar/.7z droppers --------------
# BEST-EFFORT: a 7z copy failure must NOT sink the (verified) code update — we warn
# and press on to the snapshot. Target C:\Users\Public\argus-tools, which the
# automation user can always write (C:\Tools may carry an admin-only ACL -> the
# 'access rights to this file' error). _extract_with_7z searches this path.
if ($With7z) {
    $guestToolDir = "C:\Users\Public\argus-tools"
    Write-Host "  installing 7-Zip into guest $guestToolDir (for .rar/.7z samples)"
    $hzExe = @("C:\Program Files\7-Zip\7z.exe","C:\Program Files (x86)\7-Zip\7z.exe") |
             Where-Object { Test-Path $_ } | Select-Object -First 1
    $hzDll = if ($hzExe) { Join-Path (Split-Path $hzExe) "7z.dll" } else { $null }
    if (-not $hzExe -or -not (Test-Path $hzDll)) {
        Write-Host "    ! 7-Zip not found on host — skipping (.rar stays unsupported; zip/nested-zip/.js still work)" -ForegroundColor DarkYellow
    } else {
        # stage to a plain user-owned temp dir first: vmrun can't always read the
        # Program Files copy directly ('access rights to this file').
        $stage7 = Join-Path $env:TEMP "argus-7z"
        New-Item -ItemType Directory -Force $stage7 | Out-Null
        Copy-Item $hzExe (Join-Path $stage7 "7z.exe") -Force
        Copy-Item $hzDll (Join-Path $stage7 "7z.dll") -Force
        $mk = "New-Item -ItemType Directory -Force '$guestToolDir' | Out-Null; exit 0"
        & $VMRUN @($auth + @("runProgramInGuest",$Vmx,$gps,"-NoProfile","-ExecutionPolicy","Bypass","-Command",$mk)) 2>&1 | Out-Null
        & $VMRUN @($auth + @("copyFileFromHostToGuest",$Vmx,(Join-Path $stage7 "7z.exe"),"$guestToolDir\7z.exe")) 2>&1 | Out-Null
        $exeOk = $LASTEXITCODE -eq 0
        & $VMRUN @($auth + @("copyFileFromHostToGuest",$Vmx,(Join-Path $stage7 "7z.dll"),"$guestToolDir\7z.dll")) 2>&1 | Out-Null
        $dllOk = $LASTEXITCODE -eq 0
        if ($exeOk -and $dllOk) {
            Write-Host "    copied 7z.exe + 7z.dll -> $guestToolDir" -ForegroundColor Green
        } else {
            Write-Host "    ! 7-Zip copy failed (exe=$exeOk dll=$dllOk) — continuing WITHOUT .rar; code+baseline still saved" -ForegroundColor DarkYellow
        }
    }
}

# --- 4. Bring the guest to the snapshot power state (never a hard stop) ---------
if ($Suspend) {
    # FAST-RESUME baseline: suspend to RAM so every hunt reverts to a LIVE, logged-
    # in desktop in ~5-10s instead of a full ~30-90s Windows boot. Suspend writes
    # the memory image and powers down cleanly -> the disk chain stays intact.
    Write-Host "  suspending guest (fast-resume baseline)..."
    VM ($base + @("suspend",$Vmx)) | Out-Null
} else {
    Write-Host "  shutting the guest down cleanly..."
    VMtry ($base + @("stop",$Vmx,"soft"))
}
$stopped = $false; $deadline = (Get-Date).AddSeconds(180)
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 4
    if (-not (((& $VMRUN @($base + @("list")) 2>&1) -join "`n") -match [regex]::Escape($Vmx))) { $stopped = $true; break }
}
if (-not $stopped) { throw "guest did not reach a stopped/suspended state within 180s (do NOT hard-stop)" }
Write-Host ("  " + $(if ($Suspend) { "suspended (fast-resume)" } else { "powered off" })) -ForegroundColor Green

# --- 5. Replace the CLEANBASELINE snapshot -------------------------------------
Write-Host "  re-taking snapshot '$Snapshot'"
VMtry ($base + @("deleteSnapshot",$Vmx,$Snapshot))   # non-fatal if it was already gone
VM  ($base + @("snapshot",$Vmx,$Snapshot)) | Out-Null

$mode = if ($Suspend) { "SUSPENDED (resumes in seconds — no boot)" } else { "powered-off" }
Write-Host "`n== baseline updated: '$Snapshot' [$mode] with recursive-unpack + settle-window + latest autohunt ==" -ForegroundColor Cyan
Write-Host "Run your hunt again:" -ForegroundColor Cyan
Write-Host "  .\scripts\autonomous.ps1 -Vmx `"$Vmx`" -VmPassword $VmPassword -GuestUser $GuestUser -GuestPassword $GuestPassword -HostRunsDir C:\argus-results\runs"
Write-Host "`nTip: for .rar samples, put 7z.exe in C:\Tools INSIDE the guest before running this, so it's baked into the snapshot." -ForegroundColor DarkGray
