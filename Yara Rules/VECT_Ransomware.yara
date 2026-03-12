rule VECT_Ransomware
{
    meta:
        description ="Detects activity associated with VECT ransomware. This includes registry modifications and deletions, execution of system and defense-evasion commands, suspicious API usage, mutex creation, file and memory manipulation, ransomware note generation, anti-debugging and anti-analysis techniques, and embedded cryptographic constants (SHA256) characteristic of this malware family. Designed for threat intelligence and malware detection environments."
        author = "Mustafa Bakhit"
        date = "2026-03-01"
        yarahub_author_twitter = "@mustafabakhi0x"
        yarahub_reference_link = "https://github.com/Mustafa-Bakhit0X/Cyber-Threat-Intelligence-Report-VECT-Ransomware"
        yarahub_reference_md5 = "207b1a60f803d348c795d382f5aed9c3"
        yarahub_uuid = "b7a1c9ea-1234-4e8a-a5f2-abcdef123456"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:GREEN"

    strings:
        //
        // Registry modifications / deletions
        //
        $reg_mod1 = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\vect"
        $reg_mod2 = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\vect"
        $reg_mod3 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\vect"
        $reg_mod4 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableTaskMgr"
        $reg_mod5 = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\VSS\\Diag"
        $reg_del1 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\WindowsSelfHost\\FIDs\\AllFlights"

        //
        // Commands / defense evasion
        //
        $cmd1 = "Set-MpPreference -DisableRealtimeMonitoring"
        $cmd2 = "Set-MpPreference -DisableBehaviorMonitoring"
        $cmd3 = "Set-MpPreference -DisableIOAVProtection"
        $cmd4 = "Set-MpPreference -DisableScriptScanning"
        $cmd5 = "vssadmin delete shadows /all /quiet"
        $cmd6 = "WerFault.exe -u -p"
        $cmd7 = "wbem\\wmiprvse.exe -secured -Embedding"
        $cmd8 = "DllHost.exe /Processid"
        $cmd9 = "vssvc.exe"
        $cmd10 = "svchost.exe -k swprv"
        $cmd11 = "sppsvc.exe"
        $cmd12 = "wevtutil cl \"Application\""
        $cmd13 = "wevtutil cl \"Security\""
        $cmd14 = "wevtutil cl \"System\""
        $cmd15 = "wevtutil cl \"Windows PowerShell\""

        //
        // APIs
        //
        $api1 = "RtlWow64GetCurrentMachine"
        $api2 = "RtlWow64IsWowGuestMachineSupported"
        $api3 = "NtSuspendProcess"
        $api4 = "NtResumeProcess"

        //
        // Mutexes
        //
        $mutex1 = "Local\\SM0:5780:304:WilStaging_02"
        $mutex2 = "Local\\SM0:4068:304:WilStaging_02"
        $mutex3 = "Local\\SM0:4716:304:WilStaging_02"
        $mutex4 = "Local\\WERReportingForProcess1184"
        $mutex5 = "Global\\AmiProviderMutex_InventoryApplicationFile"
        $mutex6 = "Global\\e69c1388-9c2d-40aa-a678-f6c221c16169"
        $mutex7 = "Local\\SM0:4716:120:WilError_03"
        $mutex8 = "Local\\SM0:688:304:WilStaging_02"
        $mutex9 = "Local\\SM0:3304:304:WilStaging_02"

        //
        // Ransom note
        //
        $ransom1 = "!!! README !!!"
        $ransom2 = "Dear Management, all of your files have been encrypted with ChaCha20"
        $ransom3 = "Sadly, this is not the only bad news for you"
        $ransom4 = "The only way to recover your files is to get the decryption tool"
        $ransom5 = "Backup contact (Qtox)"
        $ransom6 = "Files encrypted:"
        $ransom7 = "Total size:"
        $ransom8 = "Unique ID:"
        $ransom9 = "!!!_READ_ME_!!!.txt"
        $ransom10 = "ChaCha20"

        //
        // C2 / infrastructure
        //
        $url1 = "vectordntlcrlmfkcm4alni734tbcrnd5lk44v6sp4lqal6noqrgnbyd.onion"
        $url2 = "http://vectordntlcrlmfkcm4alni734tbcrnd5lk44v6sp4lqal6noqrgnbyd.onion/chat/"

        //
        // Anti-debugging / Anti-analysis (matched strings)
        //
        $debug1 = "IsDebuggerPresent"
        $debug2 = "CheckRemoteDebuggerPresent"
        $debug3 = "AddVectoredExceptionHandler"
        $debug4 = "RemoveVectoredExceptionHandler"
        $debug5 = "OutputDebugStringA"
        $debug6 = "SetThreadContext"

        $dbg_proc1 = "wireshark" nocase ascii wide
        $dbg_proc2 = "filemon" nocase ascii wide
        $dbg_proc3 = "procexp" nocase ascii wide
        $dbg_proc4 = "procmon" nocase ascii wide
        $dbg_proc5 = "regmon" nocase ascii wide
        $dbg_proc6 = "idag" nocase ascii wide

        //
        // Kernel32 / debugger checks
        //
        $d1 = "kernel32.dll"
        $c1 = "CheckRemoteDebuggerPresent"
        $c2 = "IsDebuggerPresent"
        $c3 = "OutputDebugString"

        //
        // File / memory / crypto
        //
        $fs1 = "VirtualAlloc"
        $fs2 = "VirtualProtect"
        $fs3 = "VirtualFree"
        $fs4 = "WriteFile"
        $fs5 = "CreateThread"
        $fs6 = "DuplicateHandle"
        $fs7 = "GetProcAddress"
        $fs8 = "LoadLibraryW"
        $fs9 = "CreateToolhelp32Snapshot"
        $fs10 = "Process32FirstW"
        $fs11 = "Process32NextW"
        $fs12 = "OpenProcess"
        $fs13 = "TerminateProcess"
        $crypto = "SystemFunction036"

        //
        // SHA256 constants (matched only)
        //
        $sha256_init0 = { 67 E6 09 6A }
        $sha256_init1 = { 85 AE 67 BB }
        $sha256_k0  = { 98 2F 8A 42 }
        $sha256_k1  = { 91 44 37 71 }
        $sha256_k2  = { CF FB C0 B5 }
        $sha256_k3  = { A5 DB B5 E9 }

    condition:
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x4550 and
        filesize < 2MB and
        (
            any of ($reg_mod*) or any of ($reg_del*) or
            any of ($cmd*) or any of ($api*) or any of ($mutex*) or
            3 of ($ransom*) or
            (any of ($url*) and any of ($crypto, $debug*)) or
            any of ($fs*) or
            any of ($sha256_init*, $sha256_k*) or
            3 of ($dbg_proc*) or
            any of ($d1, $c1, $c2, $c3)
        )
}