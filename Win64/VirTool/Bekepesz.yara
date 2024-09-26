rule VirTool_Win64_Bekepesz_A_2147921769_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Bekepesz.A!MTB"
        threat_id = "2147921769"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Bekepesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b8 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? 48 83 f8 ff 0f 95 c0 84 c0 ?? ?? ?? ?? ?? ?? ?? ?? ?? 49 89 c0 ?? ?? ?? ?? ?? ?? ?? 48 c7 c1 01 00 00 80 [0-19] 48 89 c1 ?? ?? ?? ?? ?? 83 c0 01 48 8b 8d e0 00 00 00 89 44 24 28 ?? ?? ?? ?? 48 89 44 24 20 41 b9 01 00 00 00 41 b8 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {49 89 d0 48 ?? ?? ?? ?? ?? ?? 48 89 c1 [0-19] 48 89 c1 [0-18] 48 89 c1 [0-19] 48 89 c1 ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 b8 01 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 c1}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 c1 e8 ?? ?? ?? ?? 48 8b 45 78 48 89 c1 [0-18] 48 89 c1 48 8b 05 d5 b2 00 00 ?? ?? 48 89 45 48 48 83 7d 48 00 ?? ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? ?? ?? ?? ?? 49 89 c0}  //weight: 1, accuracy: Low
        $x_1_4 = {55 53 48 81 ec a8 02 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 8d 40 02 00 00 48 89 95 48 02 00 00 ?? ?? ?? ?? 48 8b 8d 48 02 00 00 41 b9 00 00 00 00 41 b8 00 02 00 00 48 89 c2 48 8b 05 42 ac 00 00 ?? ?? 89 85 1c 02 00 00 83 bd 1c 02 00 00 ff [0-19] 48 89 c1 [0-25] 49 89 d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

