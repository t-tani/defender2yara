rule TrojanDropper_Win64_SalatStealer_ERK_2147978054_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/SalatStealer.ERK!MTB"
        threat_id = "2147978054"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "updater_" ascii //weight: 1
        $x_1_2 = "main.PayloadContainer" ascii //weight: 1
        $x_1_3 = "uac.RunDefaultUAC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

