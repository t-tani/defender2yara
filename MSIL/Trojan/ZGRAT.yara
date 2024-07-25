rule Trojan_MSIL_ZGRAT_RDE_2147908022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZGRAT.RDE!MTB"
        threat_id = "2147908022"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZGRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 53 00 00 0a 6f 54 00 00 0a 13 05 73 55 00 00 0a 0c 02}  //weight: 2, accuracy: High
        $x_2_2 = {11 04 08 6f 58 00 00 0a 02 08 6f 59 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

