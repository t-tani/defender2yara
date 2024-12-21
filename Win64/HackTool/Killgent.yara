rule HackTool_Win64_Killgent_DA_2147928862_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Killgent.DA!MTB"
        threat_id = "2147928862"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Killgent"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BYOVD Process Killer" ascii //weight: 1
        $x_1_2 = "BlackSnufkinKills" ascii //weight: 1
        $x_1_3 = "[!] Killing process:" ascii //weight: 1
        $x_1_4 = "viragt64.sys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

