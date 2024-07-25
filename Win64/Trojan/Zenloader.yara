rule Trojan_Win64_Zenloader_DA_2147916895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zenloader.DA!MTB"
        threat_id = "2147916895"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zenloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "AbsoluteClientMain" ascii //weight: 20
        $x_1_2 = "runmodule" ascii //weight: 1
        $x_1_3 = "#5002#" ascii //weight: 1
        $x_1_4 = "#5004#" ascii //weight: 1
        $x_1_5 = "#5006#" ascii //weight: 1
        $x_1_6 = "#5008#" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

