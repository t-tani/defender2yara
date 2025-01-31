rule Trojan_Win32_Lummac_GA_2147916810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lummac.GA!MTB"
        threat_id = "2147916810"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lummac"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ce 31 c4 cf c7 40 ?? 3a cd fe cb c7 40 ?? 36 c9 3c c7 c7 40 ?? 32 c5 c4 c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lummac_BZ_2147927285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lummac.BZ!MTB"
        threat_id = "2147927285"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lummac"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 44 24 0c 83 6c 24 ?? ?? 83 6c 24 ?? ?? 8a 44 24 ?? 30 04 2f 83 fb 0f 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lummac_BZ_2147927285_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lummac.BZ!MTB"
        threat_id = "2147927285"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lummac"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 20 20 00 20 20 20 20 00 40 05 00 00 10 00 00 00 58 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 b0 02 00 00 00 50 05 00 00 02 00 00 00 68 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lummac_SC_2147931978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lummac.SC"
        threat_id = "2147931978"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lummac"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 89 e5 83 e4 f8 83 ec 10 dd 45 08 dd 54 24 08 8b 4c 24 0c 89 ca c1 ea 14 81 e2 ff 07 00 00 81 fa ff 07 00 00 74 25 66 b8 ff ff 85 d2 75 31 dd 1c 24 b8 ff ff ff 7f 23 44 24 04 31 c9 0b 04 24}  //weight: 10, accuracy: High
        $x_10_2 = {b0 40 c3 b0 3f c3 89 c8 04 d0 3c 09 77 06 80 c1 04 89 c8 c3}  //weight: 10, accuracy: High
        $x_10_3 = {b0 40 c3 b0 3f c3 80 f9 30 72 ?? 80 f9 39 77 06 80 c1 04 89 c8 c3}  //weight: 10, accuracy: Low
        $x_10_4 = {8b 4c 24 04 8b 14 24 31 ca f7 d2 21 ca 29 d0}  //weight: 10, accuracy: High
        $x_10_5 = {89 f1 c1 e9 0c 80 c9 e0 88 08 89 f1 c1 e9 06 80 e1 3f 80 c9 80 88 48 01 80 e2 3f}  //weight: 10, accuracy: High
        $x_10_6 = {32 1d 30 f9 48 77 82 5a 3c bf 73 7f dd 4f 15 75}  //weight: 10, accuracy: High
        $x_5_7 = {02 0f b7 16 83 c6 02 66 85 d2 75 ef 66 c7 00 00 00 0f b7 11}  //weight: 5, accuracy: High
        $x_5_8 = {0c 0f b7 4c 24 04 66 89 0f 83 c7 02 39 f7 73 0c 01 c3 39 eb}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

