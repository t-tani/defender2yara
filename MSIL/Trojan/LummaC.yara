rule Trojan_MSIL_LummaC_CXII_2147852915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.CXII!MTB"
        threat_id = "2147852915"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 03 03 28 ?? ?? ?? ?? 17 59 fe 01 13 05 38 ?? ?? ?? ?? 02 02 8e 69 17 59 91 1f 70 61 13 01 38}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_CXIJ_2147852916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.CXIJ!MTB"
        threat_id = "2147852916"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 02 11 04 02 11 04 91 11 01 61 11 00 11 03 91 61 d2 9c 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_GZZ_2147905284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.GZZ!MTB"
        threat_id = "2147905284"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8f 1b 00 00 01 25 71 1b 00 00 01 1f 2e 58 d2 81 1b 00 00 01}  //weight: 10, accuracy: High
        $x_1_2 = "IKnkcnjbzjZBoaa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_MBZQ_2147905431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.MBZQ!MTB"
        threat_id = "2147905431"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0b 07 1f 20 8d 1e 00 00 01 25 d0 ce 00 00 04 28 ?? 00 00 0a 6f 8f 00 00 0a 07 1f 10}  //weight: 3, accuracy: Low
        $x_2_2 = {52 75 6e 6e 69 6e 67 2e 65 78 65 00 3c 4d 6f 64 75 6c 65 3e 00 43 6f 72 72 65 63 74 00 4d 53 47}  //weight: 2, accuracy: High
        $x_2_3 = {67 42 4d 74 68 65 70 6f 5a 53 4c 31 5a 56 4b 70 65 41 00 55 77 56 75 71 4c 6c 4c 4a 76 70 72 41 6f 53 33 66 63 00 50 51}  //weight: 2, accuracy: High
        $x_1_4 = "Angelo" ascii //weight: 1
        $x_1_5 = "Correct" ascii //weight: 1
        $x_1_6 = "RemoteObjects" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_MBZR_2147905432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.MBZR!MTB"
        threat_id = "2147905432"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {52 65 76 65 72 62 6e 61 74 69 6f 6e 2e 65 78 65 00 3c 4d 6f 64 75 6c 65 3e 00 43 6f 72 72 65 63 74 00 4d 53 47 5f 4e 45 54 00 4f 62 6a 65 63 74 00 50 72 6f 67 72 61 6d 00 41 6e 67 65 6c 6f 00 44 67 61 73 79 75 64 67 75 79 67 69 75 78 48}  //weight: 1, accuracy: High
        $x_1_2 = {66 4a 68 69 73 75 41 49 55 4f 00 54 68 72 53 67 74 72 6a 79 74 00 52 65 6d 6f 74 65 4f 62 6a 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_MBZR_2147905432_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.MBZR!MTB"
        threat_id = "2147905432"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 2b 03 17 2b 00 3a ?? 00 00 00 06 6f ?? 03 00 0a 11 06 6f ?? 03 00 0a 16 73 58 03 00 0a 13 0d 11 0d 11 07 28 4f 18 00 06 de 14 11 0d}  //weight: 1, accuracy: Low
        $x_1_2 = {2b 21 02 7b ?? 05 00 04 07 06 6f ?? ?? ?? 0a 20 ?? 1d 1b be 20 ?? 35 de fb 58 20 ?? 6b 14 ed 61 6a 61 9f 07 20 a3 0c 4d c8}  //weight: 1, accuracy: Low
        $x_5_3 = "Rpyoidpf." ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_LummaC_MBZS_2147905667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.MBZS!MTB"
        threat_id = "2147905667"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6f 72 00 00 0a 07 08 6f 73 00 00 0a 13 05 28 ?? 00 00 06 13 06 11 06 11 05 17 73 74 00 00 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {43 61 73 69 73 2e 65 78 65 00 3c 4d 6f 64 75 6c 65 3e 00 43 6f 72 72 65 63 74 00 4d 53 47 5f 4e 45 54 00 4f 62 6a 65 63 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_AMME_2147905753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.AMME!MTB"
        threat_id = "2147905753"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 11 11 8f ?? 00 00 01 25 71 ?? 00 00 01 11 ?? 11 ?? 28 ?? 00 00 06 a5 ?? 00 00 01 61 d2 81}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_MBZU_2147906055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.MBZU!MTB"
        threat_id = "2147906055"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 71 1a 00 00 01 20 88 00 00 00 61 d2 81 1a 00 00 01 03 50 06 ?? 1a 00 00 01 25 71 1a 00 00 01 1f 2e 58 d2}  //weight: 1, accuracy: Low
        $x_1_2 = {46 72 69 65 6e 64 6c 79 2e 65 78 65 00 4b 74 7a 78}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_ASGE_2147906192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.ASGE!MTB"
        threat_id = "2147906192"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "QzpcV2luZG93c1xNaWNyb3NvZnQuTkVUXEZyYW1ld29ya1x2NC4wLjMwMzE5XE1TQnVpbGQuZXhl" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_MBZT_2147906603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.MBZT!MTB"
        threat_id = "2147906603"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {43 6f 72 72 65 63 74 00 4d 53 47 5f 4e 45 54 00 4f 62 6a 65 63 74 00 50 72 6f 67 72 61 6d 00 41 6e 67 65 6c 6f [0-96] 52 65 6d 6f 74 65 4f 62 6a 65 63 74 73}  //weight: 10, accuracy: Low
        $x_1_2 = "RijndaelManaged" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_MBZV_2147907026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.MBZV!MTB"
        threat_id = "2147907026"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3c 4d 6f 64 75 6c 65 3e 00 43 6f 72 72 65 63 74 00 4d 53 47 5f 4e 45 54 00 4f 62 6a 65 63 74 00 3c 3e 63 5f 5f 44 69 73 70 6c 61 79 43 6c 61 73 73 35}  //weight: 1, accuracy: High
        $x_1_2 = "rivateImplementationDetails>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_CCID_2147909161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.CCID!MTB"
        threat_id = "2147909161"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 08 03 08 1f 09 5d 9a 28 ?? 00 00 0a 02 08 91 28 ?? 00 00 06 b4 9c 08 17 d6 0c 08 07 31 e1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_MDAA_2147909719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.MDAA!MTB"
        threat_id = "2147909719"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 07 02 07 91 66 d2 9c 02 07 8f ?? 00 00 01 25 71 ?? 00 00 01 1f 72 58 d2 81 ?? 00 00 01 02 07 8f ?? 00 00 01 25 71 ?? 00 00 01 1f 34 59 d2 81 ?? 00 00 01 00 07 17 58 0b}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_RDA_2147911388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.RDA!MTB"
        threat_id = "2147911388"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 04 60 03 66 04 66 60 5f 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_AMAJ_2147915323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.AMAJ!MTB"
        threat_id = "2147915323"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 5d 91 13 ?? 11 ?? 08 20 00 01 00 00 5d 58 11 ?? 58 20 00 01 00 00 5d 13 ?? 11 ?? 11 ?? 19 5a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2}  //weight: 2, accuracy: Low
        $x_1_2 = {5a 20 00 01 00 00 5d d2 0c 06 07 08 9c 00 07 17 58 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_AZ_2147917091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.AZ!MTB"
        threat_id = "2147917091"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ZCnwQyuczHNVZsLbVfaNtAuK.dll" ascii //weight: 1
        $x_1_2 = "VGFmjPREyWEsbjHmeHebQcQAmJ" ascii //weight: 1
        $x_1_3 = "LcrVaCVWmQbNGePKXQvFtVyp" ascii //weight: 1
        $x_1_4 = "YsooMXpGMiFwvybtqHIkaTRdC" ascii //weight: 1
        $x_1_5 = "cTnXHzFElfSUJxItbwZosDJXAsr" ascii //weight: 1
        $x_1_6 = "PfdxUKDVsmHGffSewIrTbKRl.dll" ascii //weight: 1
        $x_1_7 = "XcDvbkQnFxVKtUKZuwJGytHA.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_ASI_2147917450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.ASI!MTB"
        threat_id = "2147917450"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qzekfGDlOWqqjFUbvVomt.dll" ascii //weight: 1
        $x_1_2 = "qtKXquyyZSHQAVEPow.dll" ascii //weight: 1
        $x_1_3 = "etzxpPqlTDXRFxYUWstnmRWizVO" ascii //weight: 1
        $x_1_4 = "rtFQzEWPdrWnkSRhzczkNOVpBFy" ascii //weight: 1
        $x_1_5 = "AMtNVpbyBnJSKkhMOPgMUVSfqRTO.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_AMAF_2147919284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.AMAF!MTB"
        threat_id = "2147919284"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {91 66 d2 9c 02 11 ?? 8f ?? 00 00 01 25 71 ?? 00 00 01 20 ?? ?? ?? ?? 58 d2 81 ?? 00 00 01 02 11 ?? 8f ?? 00 00 01 25 71 ?? 00 00 01 1f ?? 59 d2 81 ?? 00 00 01 00 11 ?? 17 58 13 ?? 11 ?? 02 8e 69 fe}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_EZ_2147919555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.EZ!MTB"
        threat_id = "2147919555"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "375c5eff-0650-4301-85ef-382cfefa9adf" ascii //weight: 2
        $x_2_2 = "c:\\56zm\\xzd9\\obj\\Releas\\Zaq1.pdbpdb" ascii //weight: 2
        $x_1_3 = "CallWindowProcA" ascii //weight: 1
        $x_1_4 = "Pewterer Hearses Intersession" ascii //weight: 1
        $x_1_5 = "Bargello Encirclements" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_AMAK_2147920636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.AMAK!MTB"
        threat_id = "2147920636"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 00 01 00 00 5d 0d 06 08 91 13 ?? 06 08 06 09 91 9c 06 09 11 ?? 9c 06 08 91 06 09 91 58 20 00 01 00 00 5d 13 [0-80] 91 61 d2 81 [0-15] 11 13 17 58 13 13 11 13 03 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_AMA_2147921040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.AMA!MTB"
        threat_id = "2147921040"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 5b 26 11 ?? 6e 11 ?? 6a 5b 26 11 [0-50] 0a 26 03 11 ?? 8f ?? 00 00 01 25 71 ?? 00 00 01 06 11 ?? 91 61 d2 81 ?? 00 00 01 de 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_AMA_2147921040_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.AMA!MTB"
        threat_id = "2147921040"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {9c 06 08 91 06 09 91 58 20 00 01 00 00 5d 13 [0-50] 03 11 ?? 28 ?? 00 00 0a 8f ?? 00 00 01 25 71 ?? 00 00 01 06 11 ?? 28 ?? 00 00 0a 91 61 d2 81 ?? 00 00 01 de}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_WQAA_2147921642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.WQAA!MTB"
        threat_id = "2147921642"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "KRevolutionizing renewable energy with advanced solar and storage solutions." ascii //weight: 2
        $x_2_2 = "HelioCore Energy Suite" ascii //weight: 2
        $x_1_3 = "HelioCore Innovations Inc." ascii //weight: 1
        $x_1_4 = "HelioCore Innovations Trademark" ascii //weight: 1
        $x_1_5 = "$b7c8d9e0-f1a2-4324-bd5e-67890abcdef0" ascii //weight: 1
        $x_1_6 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaC_WSAA_2147921643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaC.WSAA!MTB"
        threat_id = "2147921643"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "LPioneering the future of technology with innovative and efficient solutions." ascii //weight: 2
        $x_2_2 = "Element IO Innovations Inc." ascii //weight: 2
        $x_1_3 = "Element IO Advanced Suite" ascii //weight: 1
        $x_1_4 = "Element IO Innovations Trademark" ascii //weight: 1
        $x_1_5 = "$0c784f02-e0f5-43a1-947a-aea218fd31df" ascii //weight: 1
        $x_1_6 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

