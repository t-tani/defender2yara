rule VirTool_Win64_Sebesz_A_2147979399_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Sebesz.A"
        threat_id = "2147979399"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Sebesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 85 08 01 00 00 c7 44 24 20 04 00 00 00 41 b9 00 10 00 00 49 89 d0 ba 00 00 00 00 48 89 c1 48 8b ?? ?? ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_2 = {4d 89 c1 49 89 c8 48 89 c1 48 8b ?? ?? ?? ?? ?? ff ?? 48 8b ?? ?? ?? ?? ?? 48 8b 85 08 01 00 00 48 c7 44 24 30 00 00 00 00 c7 44 24 28 00 00 00 00 48 8b 95 00 01 00 00 48 89 54 24 20 49 89 c9 41 b8 00 00 00 00 ba 00 00 00 00 48 89 c1 48 8b}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 85 08 10 00 00 48 c7 44 24 30 00 00 00 00 c7 44 24 28 80 00 00 00 c7 44 24 20 02 00 00 00 41 b9 00 00 00 00 41 b8 00 00 00 00 ba 00 00 00 40 48 89 c1 48 8b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

