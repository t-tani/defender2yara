rule Trojan_Win32_PowExec_MZK_2147977781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PowExec.MZK!MTB"
        threat_id = "2147977781"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PowExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "powershell.exe" wide //weight: 2
        $x_3_2 = "-NoProfile -WindowStyle Hidden -Command" wide //weight: 3
        $x_5_3 = "iex (-join [char[]]@(0x" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

