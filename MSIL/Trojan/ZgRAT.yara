rule Trojan_MSIL_ZgRAT_KAA_2147896399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.KAA!MTB"
        threat_id = "2147896399"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {07 08 06 09 91 9c 08 17 58 0c 09 17 59 0d 09 16 2f ee}  //weight: 5, accuracy: High
        $x_1_2 = "Kfeiof" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_KAA_2147896399_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.KAA!MTB"
        threat_id = "2147896399"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 08 09 06 09 91 7e ?? 00 00 04 59 d2 9c 00 09 17 58 0d 09 06 8e 69 fe 04 13 04 11 04 2d e1}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_KAD_2147900780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.KAD!MTB"
        threat_id = "2147900780"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://1qwqewrewqweqwrqe.sbs" wide //weight: 1
        $x_1_2 = "http://www.bcmnursing.com" wide //weight: 1
        $x_1_3 = "DownloadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_KAF_2147902681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.KAF!MTB"
        threat_id = "2147902681"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 1f 30 28 ?? 00 00 2b 28 ?? 00 00 2b 13 03 38 ?? 00 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_KAG_2147902682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.KAG!MTB"
        threat_id = "2147902682"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 02 11 04 73 ?? 00 00 0a 11 03 11 01 28 ?? 00 00 2b 28 ?? 00 00 2b 7e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_SG_2147903361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.SG!MTB"
        threat_id = "2147903361"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {d0 1b 00 00 01 28 12 00 00 06 11 03 72 01 00 00 70 28 13 00 00 06 28 01 00 00 2b 28 14 00 00 06 26}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_SGA_2147903805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.SGA!MTB"
        threat_id = "2147903805"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 aa 05 00 06 0a 06 28 41 00 00 2b 28 42 00 00 2b 0a de 03}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_KAH_2147903843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.KAH!MTB"
        threat_id = "2147903843"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 1e 11 09 11 24 11 26 61 11 1b 19 58 61 11 2c 61 d2 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_KAI_2147906225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.KAI!MTB"
        threat_id = "2147906225"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 07 03 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 0c 08 59 20 00 00 01 00 58 20 00 00 01 00 5d 0d 06 09 d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_KAJ_2147906498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.KAJ!MTB"
        threat_id = "2147906498"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {52 4e 78 9b d7 bd c9 57 9f 09 f8 19 0a 88 90 63 79 23 46 23 f9 62}  //weight: 1, accuracy: High
        $x_1_2 = {86 47 cb 7d d5 fb f4 8a 66 40 bf 84 88 c5 46 db 03 ce 14 cb f0 ac ec}  //weight: 1, accuracy: High
        $x_1_3 = "Candidate.List" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_KAK_2147907585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.KAK!MTB"
        threat_id = "2147907585"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 07 18 5d 39 ?? 00 00 00 02 65 38 ?? 00 00 00 02 58 0a 07 17 58 0b 07 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_KAL_2147907619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.KAL!MTB"
        threat_id = "2147907619"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 03 11 02 28 ?? 00 00 06 5d 28 ?? 00 00 06 61 d2 9c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_KAM_2147907918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.KAM!MTB"
        threat_id = "2147907918"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8e 69 5d 1f ?? 58 1f ?? 58 1f ?? 59 1d 58 1d 59 91 61 06 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_KAN_2147910959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.KAN!MTB"
        threat_id = "2147910959"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "4AAABlAG0AYQBOAGwAYQBuAHIAZQB0A" ascii //weight: 1
        $x_1_2 = "4AYQBwAG0AbwBDAAEAAQAi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_AC_2147915836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.AC!MTB"
        threat_id = "2147915836"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 0a 06 20 ?? ?? ?? 00 28 ?? 00 00 06 6f ?? 00 00 0a 0b d0 ?? 00 00 01 28 ?? 00 00 0a 07 20 ?? ?? ?? 00 28 ?? 00 00 06 28 ?? 00 00 0a 28 ?? 00 00 2b 6f ?? 00 00 0a 26 07 0c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

