rule Trojan_MSIL_Zusy_PSOM_2147848876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSOM!MTB"
        threat_id = "2147848876"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 72 6b 11 00 70 28 ?? ?? ?? 0a 0a 06 6f ?? ?? ?? 0a 0b 07 6f ?? ?? ?? 0a 0c 7e ?? ?? ?? 0a 0d 08 73 ?? ?? ?? 0a 13 04 00 11 04 6f ?? ?? ?? 0a 0d 00 de 0d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PSPO_2147849358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSPO!MTB"
        threat_id = "2147849358"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 08 74 1f 00 00 01 74 11 00 00 01 20 f7 01 00 00 20 df 01 00 00 28 ?? ?? ?? 2b 14 06 74 10 00 00 01 20 6e 01 00 00 20 69 01 00 00 28 ?? ?? ?? 2b 20 89 00 00 00 20 ac 00 00 00 28 ?? ?? ?? 2b 13 05 11 11}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_EN_2147849810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.EN!MTB"
        threat_id = "2147849810"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fa 01 33 00 16 00 00 01 00 00 00 33 00 00 00 16 00 00 00 15 00 00 00 18 00 00 00 02 00 00 00 3b 00 00 00 0e 00 00 00 05 00 00 00 02 00 00 00 01 00 00 00 04}  //weight: 1, accuracy: High
        $x_1_2 = "Project.Rummage.exe" ascii //weight: 1
        $x_1_3 = "GetSubKeyNames" ascii //weight: 1
        $x_1_4 = "BitConverter" ascii //weight: 1
        $x_1_5 = "WebRequest" ascii //weight: 1
        $x_1_6 = "ProxyUse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PSRR_2147850754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSRR!MTB"
        threat_id = "2147850754"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0a 06 72 bb 00 00 70 6f 0b 00 00 0a 17 8d 0d 00 00 01 13 07 11 07 16 1f 0a 9d 11 07 6f 0c 00 00 0a 0b 06 6f 0d 00 00 0a 00 16 8d 0e 00 00 01 0c 00 07 13 08 16 13 09 2b 43}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PSSI_2147851036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSSI!MTB"
        threat_id = "2147851036"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 18 00 00 0a 6f ?? 00 00 0a 07 72 c9 00 00 70 73 1a 00 00 0a 08 6f ?? 00 00 0a 06 7b 05 00 00 04 6f ?? 00 00 0a 26 08 28 ?? 00 00 0a 2d 57}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PSSU_2147851382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSSU!MTB"
        threat_id = "2147851382"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 25 06 72 75 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 73 23 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 7d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_AZU_2147851741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.AZU!MTB"
        threat_id = "2147851741"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {14 0a 16 0c 16 13 05 2b 0c 00 08 17 58 0c 00 11 05 17 58 13 05 11 05 ?? ?? ?? ?? ?? fe 04 13 06 11 06 2d e5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_NY_2147851878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.NY!MTB"
        threat_id = "2147851878"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 20 31 57 57 35 5a 20 ?? ?? ?? 13 61 2b c9 00 20 ?? ?? ?? ec 2b c1 7e ?? ?? ?? 04 28 ?? ?? ?? 06 0a 07 20 ?? ?? ?? b2 5a 20 ?? ?? ?? 9f 61 2b a7 07 20 ?? ?? ?? e4 5a 20 ?? ?? ?? fa 61 2b 98}  //weight: 5, accuracy: Low
        $x_1_2 = "MemberDefRidsAllocated.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PSTN_2147851888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSTN!MTB"
        threat_id = "2147851888"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {72 11 00 00 70 72 06 01 00 70 73 11 00 00 0a 72 14 01 00 70 28 13 00 00 0a 72 52 01 00 70 28 14 00 00 0a 28 01 00 00 06 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PSTO_2147851889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSTO!MTB"
        threat_id = "2147851889"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0c 00 07 06 28 ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 26 72 f6 01 00 70 28 ?? 00 00 0a 00 00 de 1b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PSTS_2147851955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSTS!MTB"
        threat_id = "2147851955"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 99 02 00 70 28 ?? 00 00 0a 06 72 a7 02 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 06 28 ?? 00 00 0a 26}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PSTU_2147852005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSTU!MTB"
        threat_id = "2147852005"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {7d 06 00 00 04 06 03 7d 05 00 00 04 06 15 7d 03 00 00 04 06 7c 04 00 00 04 12 00 28 01 00 00 2b 06 7c 04 00 00 04 28 10 00 00 0a 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PSTX_2147852144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSTX!MTB"
        threat_id = "2147852144"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 13 00 00 0a 25 6f ?? 00 00 0a 72 01 00 00 70 72 1b 00 00 70 6f ?? 00 00 0a 02 0a 03 28 ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 26 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_NZS_2147852199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.NZS!MTB"
        threat_id = "2147852199"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 1e 17 d6 13 1e 11 09 6f ?? ?? ?? 0a 13 0a 11 1e 1b 3e ?? ?? ?? 00 11 0b 2c 3e 11 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 2c 1b 16 13 0b 11 0a 72 ?? ?? ?? 70 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 13 17 38 ?? ?? ?? 00}  //weight: 5, accuracy: Low
        $x_1_2 = "M8Y Data Mail 2 CSV" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PSTZ_2147852256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSTZ!MTB"
        threat_id = "2147852256"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 12 00 00 0a 25 72 01 00 00 70 72 49 00 00 70 6f ?? 00 00 0a 72 65 00 00 70 72 ab 00 00 70 6f ?? 00 00 0a 72 ab 00 00 70 28 ?? 00 00 0a 26 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PSUB_2147852361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSUB!MTB"
        threat_id = "2147852361"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 12 00 00 0a 72 01 00 00 70 72 47 00 00 70 6f ?? 00 00 0a 72 47 00 00 70 28 ?? 00 00 0a 26 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PSUG_2147852496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSUG!MTB"
        threat_id = "2147852496"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 07 28 1c 00 00 0a 72 91 00 00 70 73 1d 00 00 0a 13 09 11 08 72 b3 00 00 70 11 09}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_GP_2147888821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.GP!MTB"
        threat_id = "2147888821"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 1d 00 00 01 25 d0 ae 00 00 04 28 20 00 00 0a 6f ?? 00 00 0a 06 07 6f ?? 00 00 0a 17 73 81 00 00 0a 25 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_RDC_2147888828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.RDC!MTB"
        threat_id = "2147888828"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "7759b98a-dd53-478f-b0c1-0dd79a5f46a5" ascii //weight: 1
        $x_1_2 = "loader" ascii //weight: 1
        $x_1_3 = "ComputeHash" ascii //weight: 1
        $x_1_4 = "cant deobfuscate :))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PSWM_2147889431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSWM!MTB"
        threat_id = "2147889431"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {12 00 28 1a 00 00 0a 7d 20 00 00 04 12 00 15 7d 1f 00 00 04 12 00 7c 20 00 00 04 12 00 28 03 00 00 2b 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PSWN_2147889554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSWN!MTB"
        threat_id = "2147889554"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "QjAIgwSe" ascii //weight: 2
        $x_2_2 = "zkvVhsF" ascii //weight: 2
        $x_1_3 = "DebuggingModes" ascii //weight: 1
        $x_1_4 = "GetResponseStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PSWQ_2147890090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSWQ!MTB"
        threat_id = "2147890090"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {19 73 14 00 00 0a 73 15 00 00 0a 13 07 de 19 6f ?? 00 00 0a 72 65 01 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a dd f6 00 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PSXG_2147890472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSXG!MTB"
        threat_id = "2147890472"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 73 18 00 00 0a 13 04 11 04 72 45 02 00 70 72 f8 02 00 70 6f ?? 00 00 0a 00 72 f8 02 00 70 28 ?? 00 00 0a 26 02 28 ?? 00 00 06 00 00 15 28 ?? 00 00 0a 00 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PSXI_2147890550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSXI!MTB"
        threat_id = "2147890550"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 1c 00 00 0a 26 02 28 04 00 00 06 15 28 1b 00 00 0a 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_NSZ_2147891686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.NSZ!MTB"
        threat_id = "2147891686"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {20 07 00 00 00 28 ?? ?? ?? 06 3a ?? ?? ?? ff 26 06 20 ?? ?? ?? 00 0d 12 03 6f ?? ?? ?? 06 20 ?? ?? ?? 00 38 ?? ?? ?? ff 00 73 ?? ?? ?? 06 0a 16 28 ?? ?? ?? 06 39 ?? ?? ?? 00 26 20 ?? ?? ?? 00 38 ?? ?? ?? ff}  //weight: 5, accuracy: Low
        $x_1_2 = "doorinbook_847214" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_NS_2147891690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.NS!MTB"
        threat_id = "2147891690"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 1f 10 5a 13 04 1f 10 8d ?? 00 00 01 13 05 03 11 04 11 05 16 1f 10 28 ?? 00 00 0a 06 11 05 16 11 05 8e 69 6f ?? 00 00 0a 16 08 09 1f 10 5a 1f 10}  //weight: 5, accuracy: Low
        $x_1_2 = "DPApp.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_AMAC_2147892943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.AMAC!MTB"
        threat_id = "2147892943"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 08 11 04 03 11 04 91 07 61 06 09 91 61 d2 9c 09 04 6f ?? 00 00 0a 17 59 fe 01 13 05 11 05 2c 04 16 0d 2b 04 09 17 58 0d 00 11 04 17 58 13 04 11 04 03 8e 69 fe 04 13 06 11 06 2d c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_AZ_2147893304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.AZ!MTB"
        threat_id = "2147893304"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 08 11 05 11 07 11 08 11 08 8e 69 16 28 ?? 01 00 06 2d 02 1c 2a 11 05 16 e0 28 ?? 01 00 0a 7e ?? 01 00 04 11 06 11 07 16 16 e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_KA_2147896272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.KA!MTB"
        threat_id = "2147896272"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {07 08 02 08 1a 58 91 06 d2 61 d2 9c 06 17 62 06 1f 1f 63 60 0a 08 17 58 0c 08 07 8e 69 32 e1}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_AMBC_2147896567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.AMBC!MTB"
        threat_id = "2147896567"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Svdrd.exe" ascii //weight: 1
        $x_1_2 = "Svdrd.Resources.resources" ascii //weight: 1
        $x_1_3 = "AesManaged" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "DownloadString" ascii //weight: 1
        $x_1_6 = "bmV3YnRyLmV4ZQ==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PTCH_2147897001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PTCH!MTB"
        threat_id = "2147897001"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 72 97 00 00 70 0a 02 06 28 ?? 00 00 06 00 72 d5 00 00 70 0b 02 07 28 ?? 00 00 06 00 00 de 1b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PSZQ_2147897054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSZQ!MTB"
        threat_id = "2147897054"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 06 2a 00 28 ?? 00 00 06 73 01 00 00 0a 13 07 20 00 00 00 00 7e e7 08 00 04 7b 38 09 00 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PTAU_2147897057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PTAU!MTB"
        threat_id = "2147897057"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {72 59 00 00 70 a2 28 14 00 00 0a 18 28 01 00 00 2b 28 16 00 00 0a 0a 06 1f 0a 8d 23 00 00 01 25 16 7e 12 00 00 0a 6f 13 00 00 0a a2 25}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PSSZ_2147897154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSSZ!MTB"
        threat_id = "2147897154"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e 26 04 00 04 20 92 c2 66 06 28 ?? 06 00 06 28 ?? 06 00 06 0a 06 12 01 12 02 28 ?? 04 00 06 2c 12 7e f2 07 00 04 07 08 28 ?? 07 00 06 26 dd a7 01 00 00 de 03}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PTCQ_2147897341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PTCQ!MTB"
        threat_id = "2147897341"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 6f 32 00 00 06 6f 6a 00 00 0a 00 02 72 df 00 00 70 6f 60 00 00 0a 00 02 72 eb 00 00 70 6f 6b 00 00 0a 00 02}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PSPS_2147897590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSPS!MTB"
        threat_id = "2147897590"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 7b 06 00 00 04 04 6f ?? ?? ?? 0a 0b 73 ?? ?? ?? 0a 25 07 6f ?? ?? ?? 0a 72 43 01 00 70 6f 51 00 00 0a 6f 52 00 00 0a 13 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PTDX_2147898912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PTDX!MTB"
        threat_id = "2147898912"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6f 75 00 00 0a 0c 00 03 28 ?? 00 00 0a 73 77 00 00 0a 13 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_NZ_2147899461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.NZ!MTB"
        threat_id = "2147899461"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 68 00 00 0a 02 6f ?? 00 00 0a 28 ?? 00 00 0a 03 6f ?? 00 00 0a 0a 73 ?? 00 00 0a 06 6f ?? 00 00 0a 28 23 00 00 06}  //weight: 5, accuracy: Low
        $x_1_2 = "MelonSpoofer_b2.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_NZ_2147899461_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.NZ!MTB"
        threat_id = "2147899461"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 28 06 00 00 06 75 ?? ?? ?? 1b 28 ?? ?? ?? 0a 13 04 20 ?? ?? ?? 00 7e ?? ?? ?? 04 7b ?? ?? ?? 04 3a ?? ?? ?? ff 26 20 ?? ?? ?? 00 38 ?? ?? ?? ff dd ?? ?? ?? ff 20 ?? ?? ?? 00 7e ?? ?? ?? 04 7b ?? ?? ?? 04 3a ?? ?? ?? ff 26 20 ?? ?? ?? 00 38 ?? ?? ?? ff}  //weight: 5, accuracy: Low
        $x_1_2 = "Mkwimscxva.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_AMBH_2147899966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.AMBH!MTB"
        threat_id = "2147899966"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {1e 63 d1 13 12 11 14 11 09 91 13 20 11 14 11 09 11 20 11 24 61 11 1c 19 58 61 11 35 61 d2 9c 11 09 17 58}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_AF_2147900092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.AF!MTB"
        threat_id = "2147900092"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 25 25 02 28 ?? 00 00 06 6f ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 06 13 ?? 6f ?? 00 00 0a 14 26 28}  //weight: 4, accuracy: Low
        $x_4_2 = {0d 25 25 02 28 ?? 00 00 06 6f ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 06 26 6f ?? 00 00 0a 14 26 09 72}  //weight: 4, accuracy: Low
        $x_4_3 = {0d 25 25 02 28 ?? 00 00 06 6f ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 06 13 ?? 6f ?? 00 00 0a 14 26 28}  //weight: 4, accuracy: Low
        $x_1_4 = "wtools.io/code/dl" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Zusy_PTFH_2147900531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PTFH!MTB"
        threat_id = "2147900531"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6f 9c 00 00 0a 17 73 3c 00 00 0a 25 02 16 02 8e 69 6f 9d 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_KAB_2147900781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.KAB!MTB"
        threat_id = "2147900781"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a2 fd 16 f9 d4 15 f2 75 f4 2f 70 63 4f e9 b1 02 00 47 9f d1 ab 3e 73 a1 ba 5e 22}  //weight: 1, accuracy: High
        $x_1_2 = {9e fc 6b 19 f2 0a 6c f8 eb 33 23 71 c9 69 6b 90 91 63 c3 d5 d7 e7 63 f9}  //weight: 1, accuracy: High
        $x_1_3 = "aedrfbix" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PTGO_2147900968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PTGO!MTB"
        threat_id = "2147900968"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {59 07 8e 69 59 28 ?? 00 00 2b 28 ?? 00 00 2b 02 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_CCGX_2147901017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.CCGX!MTB"
        threat_id = "2147901017"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 16 11 17 9a 13 18 00 11 18 28 ?? 00 00 0a 13 19 11 19 2c 14 09 6f ?? 00 00 0a 11 18 73 ?? ?? ?? ?? 6f ?? 00 00 0a 00 00 00 de 10 25 28 ?? 00 00 0a 13 1a 00 28 ?? 00 00 0a de 00 00 00 11 17 17 d6 13 17 11 17 11 16 8e 69 fe 04 13 1b 11 1b 2d ae}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_RDF_2147901332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.RDF!MTB"
        threat_id = "2147901332"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "niggerspoofa" ascii //weight: 1
        $x_1_2 = "eacdriv" ascii //weight: 1
        $x_1_3 = "guna2Button7_Click" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_GMX_2147901404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.GMX!MTB"
        threat_id = "2147901404"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ewqeuhiwquiye32uiy43289734712984y3ui2rekjhfdskm" wide //weight: 1
        $x_1_2 = "stormss.xyz/api" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_GMY_2147901678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.GMY!MTB"
        threat_id = "2147901678"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {26 11 0a 20 ?? ?? ?? ?? 58 61 16 58 38 ?? ?? ?? ?? 08 6f ?? ?? ?? 06 2c 08 20 ?? ?? ?? ?? 25 2b 06 20 ?? ?? ?? ?? 25 26 11 0a 20 ?? ?? ?? ?? 58 61 16 58}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PTHM_2147901857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PTHM!MTB"
        threat_id = "2147901857"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6f 78 00 00 0a 17 59 28 ?? 00 00 0a 16 7e 37 00 00 04 02 1a 28 ?? 00 00 0a 11 05 0d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_SPDD_2147901980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.SPDD!MTB"
        threat_id = "2147901980"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e 03 00 00 04 6f ?? ?? ?? 0a 05 0e 08 02 8e 69 6f ?? ?? ?? 0a 0a 06 0b 2b 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PTHT_2147902042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PTHT!MTB"
        threat_id = "2147902042"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 2c 28 06 28 ?? 00 00 0a 6f 15 00 00 0a 28 ?? 00 00 2b 6f 17 00 00 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PTHX_2147902142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PTHX!MTB"
        threat_id = "2147902142"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6f fa 00 00 0a 13 04 02 0d 11 04 09 16 09 8e b7 6f f9 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_SPYY_2147902223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.SPYY!MTB"
        threat_id = "2147902223"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 08 06 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 05 58 0d 07 02 08 6f ?? ?? ?? 0a 09 61 d1 6f ?? ?? ?? 0a 26 08 17 58 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PTHZ_2147902241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PTHZ!MTB"
        threat_id = "2147902241"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {38 08 f5 ff ff 28 ?? 00 00 0a fe 0c 01 00 6f 29 00 00 0a 28 ?? 00 00 0a 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PTIB_2147902242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PTIB!MTB"
        threat_id = "2147902242"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 45 00 00 70 28 ?? 00 00 0a 6f 12 00 00 0a 6f 12 00 00 0a 6f 13 00 00 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_GPA_2147902465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.GPA!MTB"
        threat_id = "2147902465"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 0a 05 58 0e 04 5d 13 04 08 02 09 6f ?? 00 00 0a 11 ?? 61 d1 6f ?? 00 00 0a 26 00 09 17 58 0d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_LA_2147902547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.LA!MTB"
        threat_id = "2147902547"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 95 58 7e 9b 08 ?? ?? 0e 06 17 59 95 58 0e 05}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_NA_2147902552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.NA!MTB"
        threat_id = "2147902552"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "//vegax.gg/windows/ui_ver.php" ascii //weight: 5
        $x_1_2 = "VegaX\\VegaX\\obj\\Release\\Vega X.pdb" ascii //weight: 1
        $x_1_3 = "HKEY_CURRENT_USER\\Software\\VegaX" ascii //weight: 1
        $x_1_4 = "/Vega X;component/spawnablewindows/injectcode.xaml" ascii //weight: 1
        $x_1_5 = "autoexec\\vegaxfpsunlocker.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PTIG_2147902596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PTIG!MTB"
        threat_id = "2147902596"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 55 20 00 70 07 72 8f 20 00 70 6f 4d 00 00 0a 28 ?? 00 00 0a 00 73 84 00 00 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PTIH_2147902597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PTIH!MTB"
        threat_id = "2147902597"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 66 08 00 00 28 ?? 00 00 0a 00 72 01 00 00 70 28 ?? 00 00 06 28 ?? 00 00 0a 0a 06 0b 2b 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PTII_2147902639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PTII!MTB"
        threat_id = "2147902639"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 0e 00 28 ?? 00 00 0a 72 b4 04 00 70 6f 4e 00 00 0a 13 0f 11 07 11 0f 8e 69 6a 6f 4f 00 00 0a 00 11 07 6f 50 00 00 0a 13 10 11 10 11 0f 16 11 0f 8e 69 6f 51 00 00 0a 00 17 28 ?? 00 00 0a 00 11 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_AMBE_2147903242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.AMBE!MTB"
        threat_id = "2147903242"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 13 08 12 08 28 ?? 00 00 0a 28 ?? 00 00 0a 16 09 06 1a 28 ?? 00 00 0a 00 06 1a 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_NC_2147903264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.NC!MTB"
        threat_id = "2147903264"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 95 58 7e ?? 08 00 04 0e 06 17 59 95 58 0e 05 28 d5 0d 00 06 58 54 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_ND_2147903265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.ND!MTB"
        threat_id = "2147903265"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 95 58 7e ?? 08 00 04 0e 06 17 59 95 58 0e 05 28 e8 0d 00 06 58 54 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_NF_2147903271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.NF!MTB"
        threat_id = "2147903271"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 95 58 7e ?? 08 00 04 0e 06 17 59 95 58 0e 05 28 de 0d 00 06 58 54 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PTJB_2147903332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PTJB!MTB"
        threat_id = "2147903332"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 25 00 00 0a 15 16 28 ?? 00 00 0a 0b 02 28 ?? 00 00 0a 07 17 9a 6f 27 00 00 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_SPDP_2147904014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.SPDP!MTB"
        threat_id = "2147904014"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {7e 03 00 00 04 6f ?? ?? ?? 0a 05 0e 07 0e 04 8e 69 6f ?? ?? ?? 0a 0a 06 0b 2b 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_AMMB_2147904076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.AMMB!MTB"
        threat_id = "2147904076"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a fe 09 00 00 7b ?? 00 00 04 fe 09 00 00 7b ?? 00 00 04 6f ?? 00 00 0a fe 09 01 00 20 ?? ?? ?? ?? fe 09 01 00 8e 69 6f ?? 00 00 0a 2a}  //weight: 2, accuracy: Low
        $x_1_2 = "Select * from Win32_CacheMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_SPCZ_2147904269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.SPCZ!MTB"
        threat_id = "2147904269"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {07 72 01 00 00 70 6f ?? ?? ?? 0a 0c 08 17 8d 15 00 00 01 25 16 1f 0a 9d 6f ?? ?? ?? 0a 0d 28 ?? ?? ?? 0a 13 04 00 09 13 08 16 13 09 38 b3 00 00 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_NG_2147904509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.NG!MTB"
        threat_id = "2147904509"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {61 60 0a 00 09 17 58 0d 09 02 6f 19 00 00 0a fe 04 13 04 11 04}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PTIA_2147905357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PTIA!MTB"
        threat_id = "2147905357"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {58 11 04 16 08 28 ?? 00 00 0a 28 ?? 00 00 0a 11 04 16 11 04 8e 69 6f 54 00 00 0a 13 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_RDG_2147905613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.RDG!MTB"
        threat_id = "2147905613"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {7e 03 00 00 04 6f 36 00 00 0a 02 0e 04 03 8e 69 6f 37 00 00 0a 0a 06 0b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_GPAE_2147905957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.GPAE!MTB"
        threat_id = "2147905957"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_2 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Local State" ascii //weight: 1
        $x_1_3 = "\\AppData\\Roaming\\Microsoft\\protects.zip" ascii //weight: 1
        $x_1_4 = "sam.zip" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_ARAA_2147906263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.ARAA!MTB"
        threat_id = "2147906263"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\AutoTorIP\\obj\\Debug\\SecurSocks.pdb" ascii //weight: 2
        $x_2_2 = "$3158fb64-4f13-4bf9-a10d-cf776a49140f" ascii //weight: 2
        $x_2_3 = "ServerStorage" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_GPC_2147907835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.GPC!MTB"
        threat_id = "2147907835"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 03 00 00 04 6f ?? 00 00 0a 02 0e 04 03 8e 69 6f ?? 00 00 0a 0a 06 0b 2b 00 07 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_GZX_2147909114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.GZX!MTB"
        threat_id = "2147909114"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 07 11 0d 6f ?? ?? ?? 0a 13 0c 02 09 11 09 11 0c 28 ?? ?? ?? 06 13 0d 16 13 11 2b 1b 00 11 0e 11 11 8f ?? ?? ?? 01 25 47 11 0d 11 11 91 61 d2 52 00 11 11 17 58 13 11 11 11 11 0e 8e 69 fe 04 13 12 11 12 2d d7}  //weight: 10, accuracy: Low
        $x_1_2 = "Pillager.dll" ascii //weight: 1
        $x_1_3 = "TripleDESCryptoServiceProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_GZX_2147909114_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.GZX!MTB"
        threat_id = "2147909114"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "You've been hacked by Lord Farquaad" ascii //weight: 1
        $x_1_2 = "EncryptedLog.txt" ascii //weight: 1
        $x_1_3 = "KeyAndIV.txt" ascii //weight: 1
        $x_1_4 = "Seven_ProcessedByFody" ascii //weight: 1
        $x_1_5 = "Seven.dll" ascii //weight: 1
        $x_1_6 = "LogDecrypted" ascii //weight: 1
        $x_1_7 = "LogEncrypted" ascii //weight: 1
        $x_1_8 = "Open420Port" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_MSIL_Zusy_CCIB_2147909285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.CCIB!MTB"
        threat_id = "2147909285"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LogDecrypted" ascii //weight: 1
        $x_1_2 = "LogEncrypted" ascii //weight: 1
        $x_1_3 = "EncryptFileSystem" ascii //weight: 1
        $x_1_4 = "DeleteAllDriveContents" ascii //weight: 1
        $x_1_5 = "EncryptDriveContents" ascii //weight: 1
        $x_1_6 = "Open420Port" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_SPUF_2147912426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.SPUF!MTB"
        threat_id = "2147912426"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 00 08 08 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0d 02 73 18 00 00 0a 13 04 00 11 04 09 16 73 19 00 00 0a 13 05}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_MA_2147913697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.MA!MTB"
        threat_id = "2147913697"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe 0c 00 00 7e 01 00 00 04 73 23 00 00 0a fe 0c 02 00 6f 24 00 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_EC_2147914331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.EC!MTB"
        threat_id = "2147914331"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {25 16 1f 2d 9d 6f a4 00 00 0a 0c 08 16 9a 28 16 00 00 0a 08 17 9a 08 18 9a}  //weight: 5, accuracy: High
        $x_2_2 = "CensoIBGE.RemoveCadastro.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_EC_2147914331_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.EC!MTB"
        threat_id = "2147914331"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "unknownspf_loader" ascii //weight: 5
        $x_5_2 = "ahdkakhd2oiauzd9a8du0a2dua209dua289dua2980dua2908dua29dua92dua9du9a2duz" ascii //weight: 5
        $x_1_3 = "del /s /f /q C:\\Windows\\Prefetch" ascii //weight: 1
        $x_1_4 = "NTEuODkuNy4zMw==" ascii //weight: 1
        $x_1_5 = "deactivation.php?hash=" ascii //weight: 1
        $x_1_6 = "activation.php?code=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_AMAA_2147915079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.AMAA!MTB"
        threat_id = "2147915079"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0c 08 07 17 73 ?? 00 00 0a 0d 28 [0-30] 00 00 0a 09 6f ?? 00 00 0a 08 6f ?? 00 00 0a 28 ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_SSA_2147917073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.SSA!MTB"
        threat_id = "2147917073"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://103.116.105.90/kyuc1/" ascii //weight: 1
        $x_1_2 = "so2game_lite.exe" ascii //weight: 1
        $x_1_3 = "Autoupdate_bak.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_NK_2147917445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.NK!MTB"
        threat_id = "2147917445"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "2a9d7962-3566-3296-9897-138233125171" ascii //weight: 2
        $x_1_2 = "set_UseShellExecute" ascii //weight: 1
        $x_1_3 = "Koi.Properties" ascii //weight: 1
        $x_1_4 = "VirtualAllocEx" ascii //weight: 1
        $x_1_5 = "settings\\shop\\type.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_HNH_2147919603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.HNH!MTB"
        threat_id = "2147919603"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 5f 44 65 6c 65 67 61 74 65 00 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 5f 44 65 6c 65 67 61 74 65 00 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 5f 44 65 6c 65 67 61 74 65}  //weight: 3, accuracy: High
        $x_1_2 = {00 45 78 65 63 75 74 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 5a 77 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 43 72 65 61 74 65 50 72 6f 63 65 73 73 41 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 0b 6e 00 74 00 64 00 6c 00 6c 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_HNF_2147919617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.HNF!MTB"
        threat_id = "2147919617"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0c 83 45 31 c0 49 01 c9 43 8a 34 02 40 84 f6 74}  //weight: 2, accuracy: High
        $x_1_2 = {47 65 74 50 72 6f 63 41 48 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 64 64 72 65 73 73}  //weight: 1, accuracy: Low
        $x_1_3 = "CreateProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_HNI_2147919982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.HNI!MTB"
        threat_id = "2147919982"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "1D1CC35EA61331C5A85D2A960611153E37A62DCD916269D6E3B5A0DAC2EF3824" ascii //weight: 2
        $x_1_2 = {2e 65 78 65 00 46 69 6e 61 6c 55 6e 63 6f 6d 70 72 65 73 73 65 64 53 69 7a 65 00 52 74 6c 47 65 74 43 6f 6d 70 72 65 73 73 69 6f 6e 57 6f 72 6b 53 70 61 63 65 53 69 7a 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 79 73 74 65 6d 2e 4e 65 74 00 53 6f 63 6b 65 74 00 73 6f 63 6b 65 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_HNK_2147920096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.HNK!MTB"
        threat_id = "2147920096"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "YW1zaS5kbGw=" ascii //weight: 5
        $x_5_2 = "QW1zaVNjYW5CdWZmZXI=" ascii //weight: 5
        $x_1_3 = {00 47 65 74 50 72 6f 63 41 64 64 72 65 73 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_SLZ_2147921550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.SLZ!MTB"
        threat_id = "2147921550"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 0b 00 00 0a 72 01 00 00 70 28 0c 00 00 0a 6f ?? ?? ?? 0a 13 04 12 04 28 0e 00 00 0a 2d 43 02 16 7d ?? ?? ?? 04 02 11 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

