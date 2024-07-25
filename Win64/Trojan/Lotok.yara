rule Trojan_Win64_Lotok_GPC_2147902629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lotok.GPC!MTB"
        threat_id = "2147902629"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 b9 00 30 00 00 48 8b 4c 24 50 48 03 df c7 44 24 20 40 00 00 00 44 8b 43 50 8b 53 34 ff 15 ?? ?? ?? ?? 4c 8b f0 48 85 c0}  //weight: 5, accuracy: Low
        $x_5_2 = {48 03 c6 4c 89 6c 24 20 44 8b 44 18 2c 8b 54 18 24 4c 03 c1 48 8b 4c 24 50 49 03 d6 44 8b 4c 18 28}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lotok_RW_2147912063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lotok.RW!MTB"
        threat_id = "2147912063"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 89 e5 48 83 ec 08 44 8b cb 41 81 f0 6e 74 65 6c 41 81 f0 6e 74 65 6c 48 83 c0 08}  //weight: 1, accuracy: High
        $x_1_2 = "HookWnd64.EXE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lotok_RZ_2147912507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lotok.RZ!MTB"
        threat_id = "2147912507"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 c7 c1 78 56 34 12 48 ff c9 4d 33 c9 48 8b c1 75 f5 48 33 c0 48 8b c3 48 03 c2 90 90 90 49 ff ca 4d 33 db 75 da 48 33 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

