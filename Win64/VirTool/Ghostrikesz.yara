rule VirTool_Win64_Ghostrikesz_A_2147921736_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Ghostrikesz.A!MTB"
        threat_id = "2147921736"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Ghostrikesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 53 48 81 ec a8 00 00 00 [0-32] 48 89 45 18 8b 05 23 43 00 00 89 c2 ?? ?? ?? ?? 49 89 d0 ?? ?? ?? ?? ?? ?? ?? 48 89 c1 [0-19] 48 89 c1 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? 48 89 c2 ?? ?? ?? ?? 48 89 c1}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 c3 48 ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? 49 89 c0 48 89 da ?? ?? ?? ?? ?? c6 45 af 01 c7 45 a8 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? 8b 45 a8 83 f8 03 ?? ?? ?? ?? ?? ?? 48 89 c1}  //weight: 1, accuracy: Low
        $x_1_3 = {89 da 89 c1 ?? ?? ?? ?? ?? 48 89 85 80 05 00 00 [0-18] 89 c3 [0-18] 89 da 89 c1 ?? ?? ?? ?? ?? 48 89 85 78 05 00 00 [0-18] 89 c3 [0-18] 89 da 89 c1 ?? ?? ?? ?? ?? 48 89 85 70 05 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {48 89 c3 48 ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? 48 8b 45 18 49 89 d1 49 89 d8 48 89 ca 48 89 c1 ?? ?? ?? ?? ?? 84 c0 ?? ?? b8 01 00 00 00 ?? ?? b8 00 00 00 00 84 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

