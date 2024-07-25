rule Trojan_MSIL_KillProc_SK_2147895742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KillProc.SK!MTB"
        threat_id = "2147895742"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KillProc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {17 8d 1a 00 00 01 13 07 11 07 16 72 23 00 00 70 a2 11 07 73 1f 00 00 0a 0c}  //weight: 2, accuracy: High
        $x_2_2 = {11 0a 11 09 9a 13 05 11 05 6f 23 00 00 0a 09 28 24 00 00 0a 6f 25 00 00 0a 2c 07 11 05 6f 26 00 00 0a 11 09 17 d6 13 09 11 09 11 0a 8e b7 32 d0}  //weight: 2, accuracy: High
        $x_2_3 = "Payload.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

