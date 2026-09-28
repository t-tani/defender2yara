rule Trojan_MSIL_Salat_A_2147978966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Salat.A!MTB"
        threat_id = "2147978966"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Salat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {11 05 1f 10 11 08 58 91 11 06 11 08 91 2e 05 16 13 07 2b 0b 11 08 17 58 13 08 11 08 1a 32 e1}  //weight: 20, accuracy: High
        $x_15_2 = {13 14 11 14 28 ?? ?? ?? 0a 13 15 11 15 28 ?? ?? ?? 0a 2d 1b 11 15 28 ?? ?? ?? 0a 2d 12 11 15 28 ?? ?? ?? 0a 26 11 15}  //weight: 15, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

