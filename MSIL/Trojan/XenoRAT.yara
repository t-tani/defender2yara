rule Trojan_MSIL_XenoRAT_MBYF_2147909691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XenoRAT.MBYF!MTB"
        threat_id = "2147909691"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XenoRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0c 08 03 6f ?? 00 00 0a 08 06 6f ?? 00 00 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {65 6d 6f 76 65 00 6d 61 6e 61 67 69 6e 67 5f 61 70 70 2e 65 78 65 00 63 62 53 69 7a 65 00 46 69 6e 61 6c}  //weight: 1, accuracy: High
        $x_1_3 = {54 00 61 00 73 00 6b 00 20 00 54 00 6f 00 20 00 52 00 75 00 6e 00 00 07 22 00 2c 00 22 00 00 1b 2f 00 64 00 65 00 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XenoRAT_RDA_2147912880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XenoRAT.RDA!MTB"
        threat_id = "2147912880"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XenoRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Important video file do not delete" ascii //weight: 1
        $x_1_2 = "cc7fad03-816e-432c-9b92-001f2d378390" ascii //weight: 1
        $x_1_3 = "server1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XenoRAT_SPBF_2147913670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XenoRAT.SPBF!MTB"
        threat_id = "2147913670"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XenoRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {28 04 00 00 0a 0c 00 08 03 6f 05 00 00 0a 00 08 06 6f 06 00 00 0a 00 08 08 6f 07 00 00 0a 08 6f 08 00 00 0a 6f 10 00 00 0a 0d 73 0a 00 00 0a 13 04 00 11 04 09 17 73 0b 00 00 0a 13 05 00 11 05 02 16 02 8e 69 6f 0c 00 00 0a 00 11 05 6f 0d 00 00 0a 00 11 04 6f 0e 00 00 0a 0b 00 de 0d}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XenoRAT_RDB_2147915350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XenoRAT.RDB!MTB"
        threat_id = "2147915350"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XenoRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "cc7fad03-816e-432c-9b92-001f2d378392" ascii //weight: 2
        $x_1_2 = "Display Driver Version 3" ascii //weight: 1
        $x_1_3 = "Important display driver" ascii //weight: 1
        $x_1_4 = "server1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

