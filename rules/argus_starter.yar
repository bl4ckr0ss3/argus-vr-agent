/*
   ARGUS starter YARA rules — generic static heuristics for triage.
   These are intentionally conservative starting points; add your own .yar files
   to this directory and the watcher/agent will pick them up automatically.
*/

rule UPX_Packed
{
    meta:
        description = "UPX packer markers"
    strings:
        $u0 = "UPX0"
        $u1 = "UPX1"
        $ux = "UPX!"
    condition:
        2 of them
}

rule Injection_API_Combo
{
    meta:
        description = "Classic process-injection API set"
    strings:
        $a = "VirtualAllocEx" ascii wide nocase
        $b = "WriteProcessMemory" ascii wide nocase
        $c = "CreateRemoteThread" ascii wide nocase
        $d = "NtCreateThreadEx" ascii wide nocase
        $e = "QueueUserAPC" ascii wide nocase
    condition:
        2 of them
}

rule Downloader_APIs
{
    meta:
        description = "Payload-download capability"
    strings:
        $a = "URLDownloadToFile" ascii wide nocase
        $b = "InternetOpenUrl" ascii wide nocase
        $c = "WinHttpOpen" ascii wide nocase
    condition:
        any of them
}

rule Persistence_RunKey
{
    meta:
        description = "Autorun / Run-key persistence"
    strings:
        $r = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
    condition:
        $r
}

rule Embedded_Executable
{
    meta:
        description = "More than one embedded PE (dropper/packed)"
    strings:
        $dos = "This program cannot be run in DOS mode"
    condition:
        #dos > 1
}

rule Tor_Onion_Address
{
    meta:
        description = "Embedded .onion address (Tor C2)"
    strings:
        $onion = /[a-z2-7]{16}\.onion/ nocase
        $onion3 = /[a-z2-7]{56}\.onion/ nocase
    condition:
        any of them
}

rule AntiDebug_Checks
{
    meta:
        description = "Common anti-debug API usage"
    strings:
        $a = "IsDebuggerPresent" ascii wide
        $b = "CheckRemoteDebuggerPresent" ascii wide
        $c = "NtQueryInformationProcess" ascii wide
    condition:
        2 of them
}
