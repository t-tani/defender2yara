rule Trojan_Win32_Ymacco_YAA_2147905812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ymacco.YAA!MTB"
        threat_id = "2147905812"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ymacco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 04 24 c6 00 ea 2d e3 39 46 00 05 6a 3a 46 00}  //weight: 2, accuracy: High
        $x_10_2 = {80 30 73 8b 04 24 89 c6 66 ad 89 f2 58 ff 70 fb 8f 02 b9 ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? 8d 34 08 b9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

