rule VirTool_Win64_Peleresz_A_2147979400_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Peleresz.A"
        threat_id = "2147979400"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Peleresz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 44 24 40 48 c7 44 24 38 00 00 00 00 48 c7 44 24 30 00 00 00 00 c7 44 24 28 00 00 00 08 c7 44 24 20 01 00 00 00 41 b9 00 00 00 00 41 b8 00 00 00 00 b9 00 00 00 00 48 8b}  //weight: 1, accuracy: High
        $x_1_2 = {48 89 ea 41 b8 cd 00 00 00 48 89 c1 e8 [0-17] 48 89 c1 e8 ?? ?? ?? ?? 83 f0 01 84 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {41 b8 cd 00 00 00 48 89 c1 e8 [0-25] 49 89 c8 48 89 c1 e8 ?? ?? ?? ?? 48 89 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

