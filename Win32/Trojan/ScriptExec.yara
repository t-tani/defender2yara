rule Trojan_Win32_ScriptExec_A_2147924640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ScriptExec.A"
        threat_id = "2147924640"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ScriptExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mshta.exe" ascii //weight: 1
        $x_1_2 = "Wscript.Shell" ascii //weight: 1
        $x_1_3 = "powershell.exe -nop -Command Write-Host AttackIQ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

