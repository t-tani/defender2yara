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

