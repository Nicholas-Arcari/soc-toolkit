/*
    Suspicious Windows PE Detection

    Flags PE files (EXE/DLL) that import Windows APIs commonly chained
    together for process injection or credential dumping. The APIs alone
    can be legitimate, but their co-occurrence is a strong signal.

    Reference:
        MITRE ATT&CK T1055 - Process Injection
        MITRE ATT&CK T1003 - OS Credential Dumping
*/

rule pe_process_injection_imports : pe injection
{
    meta:
        author      = "SOC Toolkit"
        description = "PE with imports typical of process injection (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread)"
        severity    = "high"
        mitre       = "T1055"
        reference   = "https://attack.mitre.org/techniques/T1055/"

    strings:
        $mz = { 4D 5A }   // DOS header

        $virtualalloc        = "VirtualAllocEx"
        $writeprocessmemory  = "WriteProcessMemory"
        $createremotethread  = "CreateRemoteThread"
        $ntmapviewofsection  = "NtMapViewOfSection"
        $ntqueueapcthread    = "NtQueueApcThread"
        $ntcreatethreadex    = "NtCreateThreadEx"
        $setwindowshookex    = "SetWindowsHookEx"

    condition:
        // Must be a PE file (DOS MZ header at offset 0)
        $mz at 0
        // Classic injection chain: allocate -> write -> execute remotely.
        // 2+ of these is unusual for benign user-mode apps
        and 2 of ($virtualalloc, $writeprocessmemory, $createremotethread,
                  $ntmapviewofsection, $ntqueueapcthread, $ntcreatethreadex,
                  $setwindowshookex)
}


rule pe_credential_dumping_imports : pe credaccess
{
    meta:
        author      = "SOC Toolkit"
        description = "PE with imports associated with LSASS/SAM credential dumping"
        severity    = "critical"
        mitre       = "T1003"
        reference   = "https://attack.mitre.org/techniques/T1003/"

    strings:
        $mz = { 4D 5A }

        // Mimikatz / LSASS dumping APIs
        $lsa_open           = "LsaOpenPolicy"
        $lsa_retrieve       = "LsaRetrievePrivateData"
        $mini_dump          = "MiniDumpWriteDump"
        $samr_enum          = "SamEnumerateUsersInDomain"
        $read_process_mem   = "ReadProcessMemory"
        $open_process_lsass = "lsass.exe" nocase

    condition:
        $mz at 0 and 2 of ($lsa_open, $lsa_retrieve, $mini_dump,
                           $samr_enum, $read_process_mem, $open_process_lsass)
}
