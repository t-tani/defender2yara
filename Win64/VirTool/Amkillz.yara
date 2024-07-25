rule VirTool_Win64_Amkillz_A_2147844671_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Amkillz.A!MTB"
        threat_id = "2147844671"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Amkillz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 12 48 c6 45 13 3f c6 45 14 3f c6 45 15 3f c6 45 16 3f c6 45 17 74 c6 45 18 33 c7 45 34 11 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 85 b8 00 00 00 48 89 44 24 20 44 8b 4d 34 4c 8d ?? ?? ba 00 04 00 00 48 8d ?? ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 04 48 8b 8d 20 01 00 00 0f b6 04 01 b9 01 00 00 00 48 6b c9 00 48 8b 95 30 01 00 00 0f b6 0c 0a 3b c1}  //weight: 1, accuracy: High
        $x_1_4 = {48 c7 44 24 20 00 00 00 00 41 b9 01 00 00 00 4c 8d ?? ?? ?? ?? ?? 48 8b 95 18 05 00 00 48 8b 4d 78 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

