rule VirTool_Win64_Stretesz_A_2147977843_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Stretesz.A"
        threat_id = "2147977843"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Stretesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 08 41 5e 48 89 f9 48 89 f2 4d 89 f1 e8 ?? ?? ?? ?? 84 c0 [0-19] 6a 0c 41 58 48 8b b5 38 07 00 00 48 89 f1 e8 ?? ?? ?? ?? 48 89 c3 49 89 d6}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 85 48 07 00 00 48 89 85 c0 04 00 00 48 8b 85 40 07 00 00 48 89 85 c8 04 00 00 ?? ?? ?? ?? ?? ?? ?? 49 89 18 ?? ?? ?? ?? ?? ?? ?? 49 89 40 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

