rule VirTool_Win64_Gheselesz_A_2147977845_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Gheselesz.A"
        threat_id = "2147977845"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Gheselesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 85 30 10 00 00 48 89 c1 e8 ?? ?? ?? ?? 48 89 c2 48 8b 85 28 10 00 00 48 8b 00 48 c7 44 24 28 00 00 00 00 c7 44 24 20 00 00 00 84 41 b9 00 00 00 00 41 b8 00 00 00 00 48 89 c1 48 8b}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 45 f0 48 3b 45 20 ?? ?? f2 0f 10 45 f8 66 0f 2e 05 03 8a 0f 00 ?? ?? f2 0f 10 45 f8 66 0f 2e 05 f4 89 0f 00}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 c1 e8 ?? ?? ?? ?? 49 89 f8 48 89 c2 48 89 d9 ff ?? 89 85 ac 01 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 c1 e8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 c1 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

