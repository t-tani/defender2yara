rule VirTool_Win64_Kheolesz_A_2147978065_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Kheolesz.A"
        threat_id = "2147978065"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Kheolesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 c9 41 b9 04 00 00 00 41 b8 00 30 00 00 ba 00 d6 0a 00 ff ?? ?? ?? ?? ?? 48 89 c1 48 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {41 0f b6 14 02 88 14 01 48 83 c0 01 48 3d 00 d6 0a 00 ?? ?? 31 d2 b8 b7 1c e8 f6 31 04 91 69 c0 0d 66 19 00 48 83 c2 01 05 5f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

