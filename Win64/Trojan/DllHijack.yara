rule Trojan_Win64_DllHijack_DA_2147845629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllHijack.DA!MTB"
        threat_id = "2147845629"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 8b 45 08 48 8d 50 f0 48 39 ca 76 ?? 48 89 c8 31 d2 4c 8b 4c 24 40 48 f7 74 24 48 49 8b 45 00 41 8a 14 11 32 54 08 10 89 c8 41 0f af c0 31 c2 88 14 0b 48 ff c1 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DllHijack_AG_2147913606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllHijack.AG!MTB"
        threat_id = "2147913606"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0f b6 08 0f b6 45 f7 48 8b 55 10 48 98 0f b6 54 02 02 4c 8b 45 ?? 48 8b 45 f8 4c 01 c0 31 ca 88 10 48 83 45 f8 01 48 8b 45 f8 48 3b 45 ?? 0f}  //weight: 4, accuracy: Low
        $x_1_2 = {b9 e8 03 00 00 48 8b 05 b1 50 01 00 ff d0 8b 05 ?? ?? ?? 00 85 c0 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

