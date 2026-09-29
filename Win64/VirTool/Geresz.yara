rule VirTool_Win64_Geresz_A_2147968577_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Geresz.A"
        threat_id = "2147968577"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Geresz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 89 c8 48 89 c1 e8 [0-17] 48 89 c1 e8 [0-37] 49 89 c8 48 89 c1 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 c1 e8 ?? ?? ?? ?? 89 c2 ?? ?? ?? ?? ?? ?? ?? 48 89 c1 e8 [0-21] 48 89 c1 e8 [0-34] 49 89 c8 48 89 c1 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {b8 00 00 00 00 84 c0 ?? ?? c7 85 cc 17 00 00 0a 00 00 00 [0-20] 48 89 c1 e8 [0-17] 48 89 c1 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Geresz_A_2147968577_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Geresz.A"
        threat_id = "2147968577"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Geresz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 84 24 c8 00 00 00 48 89 5c 24 60 48 8b 84 24 88 01 00 00 48 8b 9c 24 ?? 01 00 00 e8 ?? ?? ?? ?? 48 85 db ?? ?? ?? ?? ?? ?? 48 89 c3 ?? ?? ?? ?? ?? ?? ?? bf 07 00 00 00 ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8b 10}  //weight: 1, accuracy: Low
        $x_1_2 = {55 48 89 e5 48 83 ec 30 ?? ?? ?? ?? ?? ?? ?? bb 03 00 00 00 ?? ?? ?? ?? ?? ?? ?? bf 0e 00 00 00 e8 ?? ?? ?? ?? 48 85 c9 ?? ?? 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 66 ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

