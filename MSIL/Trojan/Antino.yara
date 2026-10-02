rule Trojan_MSIL_Antino_DA_2147979664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Antino.DA!MTB"
        threat_id = "2147979664"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Antino"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {67 68 74 20 c2 a9 20 20 32 30 32 30 00 00 29 01 00 24 62 32 62 33 61 64 62 30 2d 31 36 36 39 2d 34 62 39 34 2d 38 36 63 62 2d 36 64 64 36 38 32 64 64 62 65 61 33 00 00 0c 01 00 07 31 2e 30 2e}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

