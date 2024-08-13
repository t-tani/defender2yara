rule Trojan_MSIL_Stelpak_SK_2147918594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stelpak.SK!MTB"
        threat_id = "2147918594"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stelpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 08 08 28 17 00 00 0a 9c 73 18 00 00 0a 13 04 08 13 05 11 04 11 05 03 8e 69 5d 6f 19 00 00 0a 07 08 03 08 03 8e 69 5d 91 9c 08 17 58 0c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

