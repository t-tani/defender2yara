rule Trojan_MSIL_PureCrypter_RDA_2147843769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureCrypter.RDA!MTB"
        threat_id = "2147843769"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "d4e9ff35-13e2-4c74-a49e-ecb1eaaa3fac" ascii //weight: 1
        $x_1_2 = "File Signature Verification" ascii //weight: 1
        $x_1_3 = "Vrlawadz" ascii //weight: 1
        $x_1_4 = "//80.66.75.37/a-Xmifagl.dll" wide //weight: 1
        $x_1_5 = "Eoxhinemlvxygfpeh" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureCrypter_RDB_2147894558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureCrypter.RDB!MTB"
        threat_id = "2147894558"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6f 23 00 00 0a 28 24 00 00 0a 28 01 00 00 2b 28 02 00 00 2b 0b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureCrypter_ACP_2147894678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureCrypter.ACP!MTB"
        threat_id = "2147894678"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 27 00 00 0a 0c 00 2b 31 16 2b 31 2b 36 2b 3b 00 09 08 6f ?? ?? ?? 0a 00 00 de 11 09 2c 07 09 6f ?? ?? ?? 0a 00 19 2c f6 16 2d f9 dc 16 2d 08 08 6f ?? ?? ?? 0a 13 04 de 33 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureCrypter_PSIL_2147899375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureCrypter.PSIL!MTB"
        threat_id = "2147899375"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 03 11 02 11 04 11 02 8e 69 5d 91 11 01 11 04 91 61 d2 6f ?? ?? ?? 0a 20 ?? ?? ?? 00 7e 07 00 00 04 7b 42 00 00 04 3a 26 ff ff ff 26 20 ?? ?? ?? 00 38 1b ff ff ff 28 17 00 00 06 72 79 00 00 70 6f ?? ?? ?? 0a 13 02 38 8d ff ff ff 11 03 28 18 00 00 06 13 05 38 ?? ?? ?? 00 dd a3 00 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureCrypter_APU_2147900865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureCrypter.APU!MTB"
        threat_id = "2147900865"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {14 fe 03 13 09 20 00 00 d5 09 00 fe 0e 0e 00 00 fe 0d 0e 00 48 68 d3 13 0d 2b cb 11 09 2c 71 20 03 00 0b 7a fe 0e 0e 00 00 fe 0d 0e 00 00 48 68 d3 13 0d 2b b1 2b 00 00 11 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureCrypter_OHAA_2147912064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureCrypter.OHAA!MTB"
        threat_id = "2147912064"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 06 72 01 00 00 70 28 ?? 01 00 06 6f ?? 00 00 0a 06 72 5b 00 00 70 28 ?? 01 00 06 6f ?? 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b}  //weight: 2, accuracy: Low
        $x_2_2 = {13 04 09 11 04 16 11 04 8e 69 6f ?? 00 00 0a 09 6f ?? 00 00 0a 08 6f ?? 00 00 0a 28 ?? 00 00 0a 06}  //weight: 2, accuracy: Low
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureCrypter_UNAA_2147919645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureCrypter.UNAA!MTB"
        threat_id = "2147919645"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0b 16 0c 38 19 00 00 00 06 07 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 08 18 58 0c 08 07 6f 0d 00 00 0a 3f}  //weight: 4, accuracy: Low
        $x_1_2 = "GetByteArrayAsync" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureCrypter_URAA_2147919757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureCrypter.URAA!MTB"
        threat_id = "2147919757"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 05 2a 00 11 09 72 ?? 00 00 70 28 ?? 00 00 06 72 ?? 00 00 70 28 ?? 00 00 06 28 ?? 00 00 06 13 07}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

