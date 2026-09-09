rule VirTool_Win64_Crepesz_A_2147977844_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Crepesz.A"
        threat_id = "2147977844"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Crepesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 84 24 f0 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 48 8b 94 24 80 00 00 00 ?? ?? ?? ?? 48 83 c3 12 c7 04 02 49 89 ca b8 89 f9 88 4c 02 04 88 6c 02 05 89 fd}  //weight: 1, accuracy: Low
        $x_1_2 = {88 5c 02 11 66 c7 44 02 12 41 ff c6 44 02 14 e3 b9 04 00 00 00 e8 ?? ?? ?? ?? 48 89 c7 c7 00 01 71 07 7a b9 04 00 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

