rule Trojan_Win32_BluMnPstXplt_BB_2147977721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BluMnPstXplt.BB"
        threat_id = "2147977721"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BluMnPstXplt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "curl" wide //weight: 10
        $x_10_2 = " -sS " wide //weight: 10
        $x_10_3 = " -o " wide //weight: 10
        $x_10_4 = "http" wide //weight: 10
        $x_10_5 = "%TEMP%\\msgbox.exe" wide //weight: 10
        $x_10_6 = "&& \"%TEMP%\\msgbox.exe" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

