rule VirTool_Win64_Cookitesz_A_2147921438_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Cookitesz.A!MTB"
        threat_id = "2147921438"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Cookitesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 54 24 40 48 85 d2 [0-22] 41 b9 40 00 00 00 4c 89 64 24 20 ?? ?? ?? ?? 48 8b ce ?? ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {41 b9 30 00 00 00 ?? ?? ?? ?? ?? 49 8b d7 48 8b ce ?? ?? ?? ?? ?? ?? 48 83 f8 30 ?? ?? ?? ?? ?? ?? 81 7c 24 58 00 10 00 00 ?? ?? f6 44 24 5c 44 ?? ?? 48 8b 4c 24 50 ?? ?? ?? ?? ?? 4c 8b 4c 24 50 4c 8b e0 48 8b 54 24 38 ?? ?? ?? ?? 4d 8b c4 48 89 44 24 20 48 8b ce ?? ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {44 8b 45 98 33 f6 ?? ?? ?? ?? ?? ?? ?? 48 89 75 a0 [0-20] 45 85 c0 ?? ?? ?? ?? ?? ?? 33 d2 b9 10 04 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

