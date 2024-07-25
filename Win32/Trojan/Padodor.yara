rule Trojan_Win32_Padodor_GPB_2147903347_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Padodor.GPB!MTB"
        threat_id = "2147903347"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Padodor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {4d 5a 9b dd ff 7e 13 29 fe ab e5 60 00 d8 35 73 29 68 09 36 66 35 cf 7e f3 0d 7e 73 e5 7e 7e 90 8f 36 47 36 46 36 36 d7 8b 8b df 5e c3 7e 8b e5}  //weight: 5, accuracy: High
        $x_5_2 = {4d 5a e1 3d 08 ea f4 3f 2c 38 75 f4 98 2c 3d f4 74 4d 3d 75 3f 9d 3c 75 5d 1f b3 e6 90 3f 6e 75 3d 6e aa f4 3d 4d d7 75 38 75 4c f4 1f 75 75 3f}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Padodor_JPAA_2147906484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Padodor.JPAA!MTB"
        threat_id = "2147906484"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Padodor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 d8 01 d8 89 c3 81 eb e4 34 00 00 81 eb 3f 7a 00 00 89 d8 29 d8 89 c3 f7 e3 89 85 ?? ?? ?? ?? 89 c3 81 f3 1b 6a 00 00 89 d8 f7 e3 89 85 ?? ?? ?? ?? 89 c3 f7 e3 89 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

