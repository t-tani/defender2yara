rule VirTool_Win64_Kelesz_A_2147979888_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Kelesz.A"
        threat_id = "2147979888"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Kelesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 49 8b c2 48 f7 76 10 ?? ?? ?? ?? 48 83 7d 17 0f 48 0f 47 4d ff 41 0f b6 04 11 43 32 04 10 42 88 04 11 49 ff c2 4d 3b d5}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 44 24 60 48 85 c0 ?? ?? ?? ?? ?? ?? 33 c9 ff ?? ?? ?? ?? ?? 45 33 c9 ?? ?? ?? ?? ?? ?? ?? 4c 8b c0 b9 0d 00 00 00 ff ?? ?? ?? ?? ?? 48 8b d8 48 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {33 d2 41 b8 d0 07 00 00 ?? ?? ?? ?? e8 ?? ?? ?? ?? 41 b8 d0 07 00 00 ?? ?? ?? ?? 48 8b 5c 24 48 48 8b cb ff ?? ?? ?? ?? ?? 8b f8 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

