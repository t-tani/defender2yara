rule Trojan_MSIL_Marsilla_SK_2147919612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilla.SK!MTB"
        threat_id = "2147919612"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5f 95 d2 13 0f 11 1a 11 0f 61 13 10 11 0a 11 06 d4 11 10 d2 9c 16}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

