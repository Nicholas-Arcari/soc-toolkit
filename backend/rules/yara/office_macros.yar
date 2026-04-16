/*
    Office Macro Malware Detection

    VBA macros remain one of the top initial-access vectors for commodity
    malware (Emotet, Qakbot, IcedID). The rule flags Office documents that
    (1) have a macro-capable format AND (2) contain execution-oriented VBA
    APIs that are rare in benign documents (Shell, WScript, PowerShell,
    URLDownloadToFile).

    Reference: MITRE ATT&CK T1204.002 - User Execution: Malicious File
*/

rule office_macro_suspicious_execution : maldoc macro office
{
    meta:
        author      = "SOC Toolkit"
        description = "Office document with VBA macros invoking shell/download APIs"
        severity    = "high"
        mitre       = "T1204.002"
        reference   = "https://attack.mitre.org/techniques/T1204/002/"

    strings:
        // Container format markers
        $ole_magic = { D0 CF 11 E0 A1 B1 1A E1 }   // .doc, .xls (OLE2)
        $zip_magic = { 50 4B 03 04 }               // .docx, .xlsx (OOXML)

        // Auto-execution triggers - run as soon as user opens the file
        $vba_autoopen      = "AutoOpen" nocase
        $vba_document_open = "Document_Open" nocase
        $vba_workbook_open = "Workbook_Open" nocase
        $vba_auto_exec     = "Auto_Exec" nocase
        $vba_autoexec      = "AutoExec" nocase

        // Execution / download APIs - heavy indicators of malicious intent
        $wscript_shell   = "WScript.Shell" nocase
        $shell_run       = "Shell.Application" nocase
        $powershell      = "powershell" nocase
        $url_download    = "URLDownloadToFile" nocase
        $win_http        = "WinHttp.WinHttpRequest" nocase
        $msxml_http      = "MSXML2.ServerXMLHTTP" nocase
        $create_object   = "CreateObject" nocase

    condition:
        // Must be an Office container
        ($ole_magic at 0 or $zip_magic at 0)
        // Must have at least one auto-exec trigger
        and any of ($vba_autoopen, $vba_document_open, $vba_workbook_open,
                    $vba_auto_exec, $vba_autoexec)
        // Must have at least one execution/download API
        and any of ($wscript_shell, $shell_run, $powershell, $url_download,
                    $win_http, $msxml_http, $create_object)
}
