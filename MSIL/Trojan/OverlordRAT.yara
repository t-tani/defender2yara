rule Trojan_MSIL_OverlordRAT_FG_2147979431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/OverlordRAT.FG!MTB"
        threat_id = "2147979431"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "OverlordRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 20 ff 00 00 00 5f fe 0e 06 00 09 fe 0c 05 00 09 fe 0c 05 00 91 fe 0c 06 00 61 d2 9c fe 0c 05 00 17 58 fe 0e 05 00 fe 0c 05 00 07 32 9f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

