rule Trojan_Win64_Wingo_2147839347_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Wingo.psyA!MTB"
        threat_id = "2147839347"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Wingo"
        severity = "Critical"
        info = "psyA: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {49 3b 66 10 76 2b 48 83 ec 20 48 89 6c 24 18 48 8d 6c 24 18 48 8b 10 48 89 c3 b9 01 00 00 00 48 89 d0 e8 19 f6 ff ff 48 8b 6c 24 18 48 83 c4 20 c3 48 89 44 24 08 e8 25 06 05 00 48 8b 44 24 08 eb be}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Wingo_MA_2147846018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Wingo.MA!MTB"
        threat_id = "2147846018"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Wingo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 83 ec 60 48 89 6c 24 58 48 8d 6c 24 58 83 3d ?? ?? ?? ?? 02 ?? 0f 84 ?? ?? ?? ?? 48 85 c0 0f 84 ?? ?? ?? ?? 88 4c 24 78 48 89 5c 24 70 80 3d 65 f4 20 00 00 ?? 0f 84 80}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

