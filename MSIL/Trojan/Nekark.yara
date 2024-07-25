rule Trojan_MSIL_Nekark_MBDA_2147844514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nekark.MBDA!MTB"
        threat_id = "2147844514"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nekark"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 cf 17 00 70 6f ?? 00 00 0a 74 ?? 00 00 01 72 db 17 00 70 72 df 17 00 70 6f ?? 00 00 0a 72 e5 17 00 70 72 e9 17 00 70 6f ?? 00 00 0a 17 8d ?? 00 00 01 25 16 1f 24 9d 6f ce 00 00 0a 0b 07 8e 69 8d ?? 00 00 01 0c 16 13 04 2b 17}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nekark_2147847152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nekark!MTB"
        threat_id = "2147847152"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nekark"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Microsoft.exe" ascii //weight: 3
        $x_1_2 = "TWljcm9zb2Z0JQ==" ascii //weight: 1
        $x_1_3 = "TWljcm9zb2Z0JA==" ascii //weight: 1
        $x_1_4 = "TWljcm9zb2Z0Kg==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Nekark_MBFQ_2147899006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nekark.MBFQ!MTB"
        threat_id = "2147899006"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nekark"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "sddfhefddffjfsfkfgsacsafp" ascii //weight: 10
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nekark_KAA_2147900307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nekark.KAA!MTB"
        threat_id = "2147900307"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nekark"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 08 07 8e 69 5d 1f 09 58 1f 0c 58 1f 15 59 91 61 28 ?? 00 00 0a 03 08 20 ?? ?? 00 00 58 20 ?? ?? 00 00 59 03 8e 69 5d 91 59 20 ?? 00 00 00 58 17 58 20 00 ?? 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nekark_HDAA_2147904771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nekark.HDAA!MTB"
        threat_id = "2147904771"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nekark"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {59 91 61 02 08 20 ?? ?? 00 00 58 20 ?? ?? 00 00 59 02 8e 69 5d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nekark_IIAA_2147905610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nekark.IIAA!MTB"
        threat_id = "2147905610"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nekark"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8e 69 5d 1f 09 58 1f 0c 58 1f 15 59 91 61 04 08 20 ?? 02 00 00 58 20 ?? 02 00 00 59 1b 59 1b 58 04 8e 69 5d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nekark_NK_2147911680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nekark.NK!MTB"
        threat_id = "2147911680"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nekark"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 17 00 00 0a 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 72 ?? 00 00 70 6f 1a 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "ExclusionPath.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

