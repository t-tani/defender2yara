rule Trojan_Win32_NetUseSpray_A_2147849693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetUseSpray.A!cbl4"
        threat_id = "2147849693"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetUseSpray"
        severity = "Critical"
        info = "cbl4: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 00 65 00 74 00 2e 00 65 00 78 00 65 00 [0-64] 75 00 73 00 65 00 [0-64] 5c 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6e 00 65 00 74 00 20 00 [0-64] 75 00 73 00 65 00 [0-64] 5c 00 5c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

