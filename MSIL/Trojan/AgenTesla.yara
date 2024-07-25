rule Trojan_MSIL_AgenTesla_MBFW_2147903706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AgenTesla.MBFW!MTB"
        threat_id = "2147903706"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgenTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 9e 06 1d 06 1d 95 07 1d 95 61}  //weight: 1, accuracy: High
        $x_10_2 = {6f 00 76 00 72 00 66 00 6c 00 77 00 2e 00 65 00 78 00 65 00 00 00 00 00 22 00 01 00 01 00 50 00 72 00 6f}  //weight: 10, accuracy: High
        $x_10_3 = {45 43 58 65 76 00 41 74 74 72 69 62 75 74 65}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AgenTesla_MBYO_2147912556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AgenTesla.MBYO!MTB"
        threat_id = "2147912556"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgenTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 08 06 08 6f ?? 00 00 0a 1f ?? 61 d2 9c 08 17 58 0c 08 06 6f ?? 00 00 0a 32}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

