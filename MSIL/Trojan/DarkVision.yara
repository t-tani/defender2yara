rule Trojan_MSIL_DarkVision_AMCL_2147926943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkVision.AMCL!MTB"
        threat_id = "2147926943"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkVision"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {1e 62 60 0f ?? 28 ?? 00 00 0a 60 0a 02 06 1f 10 63 20 ff 00 00 00 5f d2 6f ?? 00 00 0a 02 06 1e 63 20 ff 00 00 00 5f d2 6f ?? 00 00 0a 02 06 20 ff 00 00 00 5f d2 6f ?? 00 00 0a 2a}  //weight: 4, accuracy: Low
        $x_1_2 = {9c 25 18 0f ?? 28 ?? 00 00 0a 9c 0b 02 07 04 28 ?? 00 00 2b 6f ?? 00 00 0a 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

