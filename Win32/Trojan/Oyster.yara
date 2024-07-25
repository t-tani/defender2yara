rule Trojan_Win32_Oyster_AA_2147908539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oyster.AA!MTB"
        threat_id = "2147908539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 c7 45 fc ?? ?? ?? ?? 8b c6 8d 0c 1e f7 75 fc 2b 55 f8 8a 44 15 ?? 32 04 39 46 88 01 81 fe ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Oyster_MKV_2147912849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oyster.MKV!MTB"
        threat_id = "2147912849"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 ca c1 e9 04 6b c1 13 8b 4d fc 2b c8 03 cf 83 c7 06 0f b6 44 0d ?? 8b 4d ec 32 04 31 8b 4d fc 88 46 05 83 c6 06 81 ff 00 62 07 00 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

