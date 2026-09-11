rule VirTool_Win64_Kheotesz_A_2147978066_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Kheotesz.A"
        threat_id = "2147978066"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Kheotesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b9 04 00 00 00 ba 00 e6 0a 00 31 c9 45 31 f6 41 b8 00 30 00 00 ff ?? ?? ?? ?? ?? 48 89 c7 48 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {31 c0 44 89 f2 41 b8 00 d6 0a 00 48 89 f1 48 01 fa 45 29 f0 89 84 24 a0 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ff ?? 85 c0 ?? ?? 8b 84 24 a0 00 00 00 85 c0 ?? ?? 41 01 c6 41 81 fe}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

