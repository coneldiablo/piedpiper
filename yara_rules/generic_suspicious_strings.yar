rule GenericSuspiciousStrings
{
    meta:
        author = "Pied Piper"
        description = "Generic strings often seen in suspicious samples"
    strings:
        $ps1 = "powershell" ascii wide nocase
        $iex = "Invoke-Expression" ascii wide nocase
        $crt = "CreateRemoteThread" ascii wide nocase
        $wpm = "WriteProcessMemory" ascii wide nocase
    condition:
        2 of them
}
