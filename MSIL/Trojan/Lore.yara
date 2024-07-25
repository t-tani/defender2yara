rule Trojan_MSIL_Lore_BZ_2147767455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lore.BZ!MTB"
        threat_id = "2147767455"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6d 61 6c 68 65 75 72 65 75 78 00 49 6d 61 67 69 6e 65 72}  //weight: 1, accuracy: High
        $x_1_2 = {65 00 78 00 61 00 67 00 e8 00 72 00 65 00 2e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

