rule VirTool_Win64_Fekilesz_A_2147979397_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Fekilesz.A"
        threat_id = "2147979397"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Fekilesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 48 89 e5 48 83 ec 50 ?? ?? ?? ?? ?? ?? ?? 48 c7 44 24 30 00 00 00 00 c7 44 24 28 80 00 00 00 c7 44 24 20 03 00 00 00 41 b9 00 00 00 00 41 b8 00 00 00 00 ba 00 00 00 c0 48 89 c1 48 8b}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 45 10 48 c7 44 24 38 00 00 00 00 ?? ?? ?? ?? 48 89 54 24 30 c7 44 24 28 00 00 00 00 48 c7 44 24 20 00 00 00 00 41 b9 08 00 00 00 49 89 c8 ba 24 20 22 00 48 89 c1 48 8b}  //weight: 1, accuracy: Low
        $x_1_3 = {b8 01 00 00 00 ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 89 45 f0 48 83 7d f0 ff ?? ?? b8 01 00 00 00 [0-25] 48 89 c1 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

