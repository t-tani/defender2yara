rule TrojanDropper_Win64_Mikey_MK_2147956277_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/Mikey.MK!MTB"
        threat_id = "2147956277"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {4d 85 c0 48 8d 41 fe 48 0f 45 c1 66 89 28 48 8b ca 48 8d 44 24 ?? 0f 1f 40 00 66 39 28}  //weight: 15, accuracy: Low
        $x_10_2 = {48 8b 9c 24 ?? ?? 00 00 4c 8b a4 24 ?? ?? 00 00 48 8b bc 24 ?? ?? 00 00 4c 8b bc 24 ?? ?? 00 00 4c 8b b4 24 ?? ?? 00 00 48 8b 8d d0 0f 00 00 48 33 cc}  //weight: 10, accuracy: Low
        $x_5_3 = "%04d-%02d-%02dT%02d:%02d:%02d" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_15_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win64_Mikey_MKA_2147956983_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/Mikey.MKA!MTB"
        threat_id = "2147956983"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {0f b7 44 44 ?? 33 c1 48 63 0c 24 66 89 44 4c ?? 48 63 04 24}  //weight: 15, accuracy: Low
        $x_10_2 = {c6 84 24 9a 00 00 00 4b c6 84 24 9b 00 00 00 00 c6 84 24 9c 00 00 00 48 c6 84 24 9d 00 00 00 00 c6 84 24 9e 00 00 00 2c}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win64_Mikey_A_2147979656_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/Mikey.A!MTB"
        threat_id = "2147979656"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_35_1 = {48 63 c8 48 b8 11 42 08 21 84 10 42 08 48 f7 e1 48 8b c1 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 05 48 6b c0 3e 48 2b c8 44 0f b7 4c 4d 90 48 3b df}  //weight: 35, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

