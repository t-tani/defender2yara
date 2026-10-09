rule VirTool_Win64_Shelanjesz_A_2147979886_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Shelanjesz.A"
        threat_id = "2147979886"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelanjesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b9 00 30 00 00 c7 44 24 20 40 00 00 00 4c 8b c3 33 d2 48 8b cd ff ?? ?? ?? ?? ?? 4c 8b f8 48 85 c0 ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_2 = {33 f6 4c 8b cb 48 89 44 24 20 4c 8b c7 48 89 74 24 30 49 8b d7 48 8b cd ff ?? ?? ?? ?? ?? 85 c0 ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_3 = {44 8b c7 33 d2 b9 10 00 00 00 ff ?? ?? ?? ?? ?? 48 8b f0 48 85 c0 ?? ?? ?? ?? ?? ?? 45 33 c0 48 8b d0 49 8b cf ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

