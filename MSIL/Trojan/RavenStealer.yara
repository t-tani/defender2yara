rule Trojan_MSIL_RavenStealer_SA_2147977783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RavenStealer.SA!MTB"
        threat_id = "2147977783"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RavenStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 02 8e 69 8d 1b 00 00 01 0b 16 0c 2b 13 07 08 02 08 91 06 08 06 8e 69 5d 91 61 d2 9c 08 17 58 0c 08 02 8e 69 32 e7}  //weight: 1, accuracy: High
        $x_1_2 = "SelfDelete" ascii //weight: 1
        $x_1_3 = "keylogTimer" ascii //weight: 1
        $x_1_4 = "UnhookWindowsHookEx" ascii //weight: 1
        $x_1_5 = "StartKeylogger" ascii //weight: 1
        $x_1_6 = "GetKeylogData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

