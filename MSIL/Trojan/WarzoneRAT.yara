rule Trojan_MSIL_WarzoneRAT_SPPX_2147906440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WarzoneRAT.SPPX!MTB"
        threat_id = "2147906440"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WarzoneRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {09 11 04 9a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 8e 2c 04 17 0a 2b 0d 11 04 17 58 13 04 11 04 09 8e 69 32 de}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

