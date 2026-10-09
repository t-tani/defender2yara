rule VirTool_Win64_Injetesz_A_2147979887_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Injetesz.A"
        threat_id = "2147979887"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Injetesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 33 c0 4c 89 74 24 68 ?? ?? ?? ?? ?? 48 c7 44 24 78 3a 00 00 00 48 8b cf c7 44 24 20 00 30 00 00 ff ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {45 33 c0 4c 89 74 24 48 ba ff ff 1f 00 4c 89 74 24 40 4c 89 74 24 38 44 89 74 24 30 48 89 44 24 28 48 89 4c 24 20 ?? ?? ?? ?? ?? 4c 89 74 24 60 ff ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 89 74 24 20 48 8b cf ff ?? 85 c0 ?? ?? 45 33 c0 ?? ?? ?? ?? ?? ?? ?? 8b d0 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

