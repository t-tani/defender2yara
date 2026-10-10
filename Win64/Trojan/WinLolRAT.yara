rule Trojan_Win64_WinLolRAT_PA_2147980089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/WinLolRAT.PA!MTB"
        threat_id = "2147980089"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "WinLolRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 31 d1 0f b6 50 ?? 44 0f b6 40 ?? 44 0f b6 48 ?? 0f b6 40 ?? c1 e0 ?? 41 c1 e1 ?? 41 09 c1 41 c1 e0 ?? 45 09 c8 41 09 d0 41 81 f0 41 df dd 45 48 89 8c 24 ?? ?? ?? ?? 44 89 84 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

