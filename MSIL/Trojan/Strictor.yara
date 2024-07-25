rule Trojan_MSIL_Strictor_PSOS_2147847839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Strictor.PSOS!MTB"
        threat_id = "2147847839"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Strictor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 28 39 00 00 0a 03 6f 3a 00 00 0a 0a 06 28 3b 00 00 0a 0b 07 0c 2b 00 08 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Strictor_KAA_2147896403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Strictor.KAA!MTB"
        threat_id = "2147896403"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Strictor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {69 5d 91 08 09 08 6f ?? 01 00 0a 5d 6f ?? 01 00 0a 61 28 ?? 01 00 0a 07 09 17 58 07 8e 69 5d 91}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Strictor_SK_2147898757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Strictor.SK!MTB"
        threat_id = "2147898757"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Strictor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 00 01 00 00 13 05 06 08 5d 13 06 06 17 58 08 5d 13 0b 07 11 0b 91 11 05 58 13 0c 07 11 06 91 13 0d 11 0d 11 07 06 1f 16 5d 91 61 13 0e 11 0e 11 0c 59 13 0f 07 11 06 11 0f 11 05 5d d2 9c 06 17 58 0a 06 08 11 08 17 58 5a fe 04 13 10 11 10 2d ae}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Strictor_MBFV_2147902999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Strictor.MBFV!MTB"
        threat_id = "2147902999"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Strictor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 08 06 07 06 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 11 08 61 13 09 06 11 06 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Strictor_NA_2147904507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Strictor.NA!MTB"
        threat_id = "2147904507"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Strictor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 2a 61 19 11 1f 58 61 11 2e 61 d2}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

