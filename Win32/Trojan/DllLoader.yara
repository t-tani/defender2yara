rule Trojan_Win32_DllLoader_NEAA_2147834124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllLoader.NEAA!MTB"
        threat_id = "2147834124"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0b d5 41 89 96 e0 00 00 00 69 47 3c 47 c0 2c 64 3b c8 75 ec}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

