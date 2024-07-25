rule Trojan_MSIL_XLoader_RDA_2147846100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XLoader.RDA!MTB"
        threat_id = "2147846100"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dkdFIh" ascii //weight: 1
        $x_2_2 = {02 08 02 8e 69 5d 91 07 08 07 8e 69 5d 91 61}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

