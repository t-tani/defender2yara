rule VirTool_Win64_Cookidumpesz_2147921646_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Cookidumpesz!MTB"
        threat_id = "2147921646"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Cookidumpesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b9 18 00 00 00 ?? ?? ?? ?? ?? 48 8b da 48 8b f9 ?? ?? ?? ?? ?? 85 c0 ?? ?? 48 8b d3 [0-20] 48 8b 54 24 30 48 85 d2}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 54 24 38 [0-18] 41 b8 08 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 8b 4c 24 38 [0-16] 48 89 44 24 20 41 b9 08 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 8b d3 [0-16] 85 c0 [0-20] 48 8b 54 24 38}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

