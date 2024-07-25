rule Trojan_MSIL_Rhadamanthys_ARH_2147841949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rhadamanthys.ARH!MTB"
        threat_id = "2147841949"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 1b 2d 03 26 2b 66 0a 2b fb 00 72 01 00 00 70 28 ?? ?? ?? 06 73 02 00 00 0a 16 2c 03 26 2b 03 0b 2b 00 73 03 00 00 0a 1b 2d 03 26 2b 03 0c 2b 00 07 16 73 04 00 00 0a 73 05 00 00 0a 0d 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rhadamanthys_NEAA_2147844545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rhadamanthys.NEAA!MTB"
        threat_id = "2147844545"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 00 06 13 00 38 00 00 00 00 28 02 00 00 0a 11 00 6f 03 00 00 0a 28 04 00 00 0a 28 05 00 00 06 13 01 38 00 00 00 00 dd 10 00 00 00 26 38 00 00 00 00 dd ?? ?? ?? ?? 38 00 00 00 00 11 01 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rhadamanthys_ARY_2147894231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rhadamanthys.ARY!MTB"
        threat_id = "2147894231"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {17 da 0b 16 0c 2b 15 03 08 03 08 9a 04 72 ?? 06 00 70 6f ?? 00 00 0a a2 08 17 d6 0c 08 07 31 e7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rhadamanthys_RS_2147899245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rhadamanthys.RS!MTB"
        threat_id = "2147899245"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 28 12 00 00 06 0a 28 03 00 00 0a 06 6f 04 00 00 0a 28 05 00 00 0a 28 01 00 00 2b 28 02 00 00 2b 0b de 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rhadamanthys_MBZU_2147906133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rhadamanthys.MBZU!MTB"
        threat_id = "2147906133"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 61 73 69 73 2e 65 78 65 00 3c 4d 6f 64 75 6c 65 3e 00 43 6f 72 72 65 63 74 00 4d 53 47 5f 4e 45 54 00 4f 62 6a 65 63 74 00 50 72 6f 67 72 61 6d 00 41 6e 67 65 6c 6f 00 44 67 61 73 79 75 64 67 75 79 67 69 75 78 48 49 41 00 4d 75 6c 74 69 63 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

