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

rule HackTool_Win64_Killgent_RPA_2147929049_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Killgent.RPA!MTB"
        threat_id = "2147929049"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Killgent"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "135"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {2e 73 79 73 5c 5c 2e 5c 20 00 2e 73 79 73 20 00 5c [0-32] 2e 73 79 73 20 00 5c 20 00 02 5c 02 2e 73 79 73 5c 5c 2e 5c}  //weight: 100, accuracy: Low
        $x_100_2 = {00 5c 00 5c 00 2e 00 5c 00 76 00 69 00 72 00 61 00 67 00 74 00 6c 00 74 00 00 00 00 00 00 00 00 00 76 00 69 00 72 00 61 00 67 00 74 00 36 00 34 00 00 00 00 00 00 00 00 00 76 00 69 00 72 00 61 00 67 00 74 00 36 00 34 00 2e 00 73 00 79 00 73}  //weight: 100, accuracy: High
        $x_10_3 = "[!] Service already exists." ascii //weight: 10
        $x_10_4 = "[!] Failed to create service." ascii //weight: 10
        $x_10_5 = "[X] Failed to initialize the driver." ascii //weight: 10
        $x_10_6 = "[X] Failed to create service. Error: " ascii //weight: 10
        $x_10_7 = "[*] Service already exists" ascii //weight: 10
        $x_10_8 = "[X] Failed to initialize driver" ascii //weight: 10
        $x_1_9 = "OpenSCManagerW" ascii //weight: 1
        $x_1_10 = "OpenServiceW" ascii //weight: 1
        $x_1_11 = "StartServiceW" ascii //weight: 1
        $x_1_12 = "StartServiceA" ascii //weight: 1
        $x_1_13 = "CloseServiceHandle" ascii //weight: 1
        $x_1_14 = "CreateServiceW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_10_*) and 5 of ($x_1_*))) or
            ((1 of ($x_100_*) and 4 of ($x_10_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

