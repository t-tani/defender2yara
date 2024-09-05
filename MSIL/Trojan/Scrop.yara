rule Trojan_MSIL_Scrop_GPA_2147920475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Scrop.GPA!MTB"
        threat_id = "2147920475"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Scrop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 04 74 4f 00 00 01 11 05 11 0a 74 0c 00 00 1b 11 0c 11 07 58 11 09 59 93 61 11 0b 75 0c 00 00 1b 11 09 11 0c 58 1f 11 58 11 08 5d 93 61 d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

