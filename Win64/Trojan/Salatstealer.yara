rule Trojan_Win64_Salatstealer_BA_2147979943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Salatstealer.BA!MTB"
        threat_id = "2147979943"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Salatstealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 f8 0f af c2 83 c0 ?? 32 44 11 ff 83 f0 ?? 88 44 13 ff eb}  //weight: 2, accuracy: Low
        $x_2_2 = {89 45 f4 8b 45 f4 8b 55 f4 c1 e8 0b 31 d0 89 45 f4 8b 45 f4 89 45 f0 ff 15}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Salatstealer_BB_2147979949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Salatstealer.BB!MTB"
        threat_id = "2147979949"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Salatstealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 29 da 4d 8d 4c 1d 00 48 39 c2 48 0f 47 d0 31 c0 49 01 d8 41 8a 0c 01 32 8c 04 ?? ?? ?? ?? 41 88 0c 00 48 ff c0 48 39 c2 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Salatstealer_BC_2147980003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Salatstealer.BC!MTB"
        threat_id = "2147980003"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Salatstealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8d 44 24 28 8d 4c 24 10 31 f6 31 ff 89 08 b9 ?? ?? ?? ?? 89 f2 0f a4 ca 03 8d 5f 01 0f a4 f1 03 83 cf 01 01 f9 89 df 83 d2 00 89 4c 24 28 81 fb ?? ?? ?? ?? 89 54 24 2c 89 d6 75}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

