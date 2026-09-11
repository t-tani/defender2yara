rule Trojan_Win64_SheetCord_PY_2147978058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SheetCord.PY!MTB"
        threat_id = "2147978058"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SheetCord"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "main.StartAgent" ascii //weight: 2
        $x_1_2 = "main.ExecuteOnce" ascii //weight: 1
        $x_1_3 = "main.GetHardwareInfo" ascii //weight: 1
        $x_1_4 = "main.RunCommand" ascii //weight: 1
        $x_1_5 = "main.GetJunkData" ascii //weight: 1
        $x_1_6 = "main.uploadHardwareInfo" ascii //weight: 1
        $x_1_7 = "main.webClient" ascii //weight: 1
        $x_1_8 = "main.runSystemCommand" ascii //weight: 1
        $x_1_9 = "main.collectSystemInfo" ascii //weight: 1
        $x_1_10 = "main.junkStringManipulation" ascii //weight: 1
        $x_1_11 = "main.getMachineName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

