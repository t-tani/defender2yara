rule Trojan_MSIL_zgRat_NF_2147847495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRat.NF!MTB"
        threat_id = "2147847495"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {fe 0c 06 00 76 6c 58 6d fe ?? ?? 00 5c fe ?? ?? 00 58 fe ?? ?? 00 fe ?? ?? 00 fe ?? ?? 00 59 20 ?? ?? ?? 0b 61 fe ?? ?? 00 20 ?? ?? ?? 00 fe ?? ?? 00 20 ?? ?? ?? 00 5f 5a}  //weight: 5, accuracy: Low
        $x_1_2 = "SX4VPBnwra" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRat_NZA_2147848258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRat.NZA!MTB"
        threat_id = "2147848258"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 0f 00 00 0a 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 0a dd ?? ?? ?? 00}  //weight: 5, accuracy: Low
        $x_1_2 = "WindowsFormsApp22.Properties" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRat_NZA_2147848258_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRat.NZA!MTB"
        threat_id = "2147848258"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 0c 00 00 06 0a 28 ?? 00 00 0a 06 6f ?? 00 00 0a 28 ?? 00 00 06 75 ?? 00 00 1b 0b 07 16 07 8e 69 28 10 00 00 0a 07}  //weight: 5, accuracy: Low
        $x_1_2 = "WindowsFormsApp57.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRat_NYN_2147850317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRat.NYN!MTB"
        threat_id = "2147850317"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {73 0c 00 00 06 28 ?? 00 00 06 28 ?? 00 00 0a 73 ?? 00 00 06 7b ?? 00 00 04 6f ?? 00 00 0a 73 ?? 00 00 06 7b ?? 00 00 04 6f ?? 00 00 0a 18 2d 04}  //weight: 5, accuracy: Low
        $x_1_2 = "Zhvmhop.Properties" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

