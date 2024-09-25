rule VirTool_Win32_Leakwall_B_2147921606_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Leakwall.B"
        threat_id = "2147921606"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Leakwall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 10 ?? ?? ?? ?? 52 56 50 8b 08 ff ?? ?? 85 c0 ?? ?? 8b ?? ?? ?? ?? ?? ba ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b c8 ff ?? ?? ?? ?? ?? 8b c8 ff ?? ?? ?? ?? ?? eb ?? 8b 44 24 10 53 ff 74 24 18 8b 08 50 ff ?? ?? 68 ?? ?? ?? ?? 51 8b ?? ?? ?? ?? ?? ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 04 8b c8 ff ?? ?? ?? ?? ?? ff 74 24 14 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {0f 57 c0 c7 44 24 44 00 00 00 00 ?? ?? ?? ?? 66 0f 13 44 24 28 50 66 0f 13 44 24 34 66 0f 13 44 24 40 ff ?? ?? ?? ?? ?? 8d ?? ?? ?? 50 57 68 ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? ?? 68 2c 01 00 00 50 e8 ?? ?? ?? ?? 83 c4 14 c7 44 24 1c 24 00 00 00 ?? ?? ?? ?? c7 44 24 30 04 00 00 00 50 ?? ?? ?? ?? 50 ?? ?? ?? ?? 50 ?? ?? ?? ?? ?? ?? ?? 50 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

