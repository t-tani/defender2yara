rule VirTool_Win64_Sheloadesz_A_2147979889_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Sheloadesz.A"
        threat_id = "2147979889"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Sheloadesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 bd b0 06 00 00 48 89 9d b8 06 00 00 89 b5 c0 06 00 00 89 85 c4 06 00 00 [0-20] 41 b8 ?? ?? 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {31 c9 48 89 f2 41 b8 00 30 00 00 41 b9 04 00 00 00 ff ?? ?? ?? ?? ?? 48 85 c0 ?? ?? ?? ?? ?? ?? 48 89 c7 48 89 c1 48 8b 9d e8 06 00 00 48 89 da 49 89 f0 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 f9 48 89 f2 41 b8 ?? ?? 00 00 ff ?? ?? ?? ?? ?? ff ?? 48 8b 95 e0 06 00 00 48 85 d2 ?? ?? 41 b8 01 00 00 00 48 89 d9 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

