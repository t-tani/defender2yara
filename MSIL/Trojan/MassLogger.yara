rule Trojan_MSIL_MassLogger_GN_2147760436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.GN!MTB"
        threat_id = "2147760436"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 0b 07 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 14 72 ?? ?? ?? 70 17 8d ?? ?? ?? 01 25 16 72 ?? ?? ?? 70 a2 14 14 28 ?? ?? ?? 0a 74 ?? ?? ?? 01 0c 00 08 14 1a 8d ?? ?? ?? 01 25 d0 ?? ?? ?? 04 28 ?? ?? ?? 0a 73 ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 18 8d ?? ?? ?? 01 25 17 03 a2 14 14 28 ?? ?? ?? 0a 26 72 ?? ?? ?? ?? 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_GN_2147760436_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.GN!MTB"
        threat_id = "2147760436"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {17 0c 19 8d ?? ?? ?? 01 13 06 11 06 16 7e ?? ?? ?? 04 a2 11 06 17 7e ?? ?? ?? 04 a2 11 06 18 20 ?? ?? ?? ?? 28 ?? ?? ?? 06 a2 11 06 73 ?? ?? ?? 06 [0-32] 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {17 13 05 17 13 06 19 8d ?? ?? ?? 01 13 07 11 07 16 7e ?? ?? ?? 04 a2 11 07 17 7e ?? ?? ?? 04 a2 11 07 18 72 ?? ?? ?? ?? a2 11 07 73 ?? ?? ?? 06 [0-32] 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_MassLogger_RM_2147763799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.RM!MTB"
        threat_id = "2147763799"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "oXCCFvgFvoMFCnfdtYEwdOHfBHtnA.resources" ascii //weight: 1
        $x_1_2 = "PpLYzkgfaYBngpiXMUeROfwGTnzE.resources" ascii //weight: 1
        $x_1_3 = "PxHmqfwUlXIcRAXxIAAcUbMcMkGj.resources" ascii //weight: 1
        $x_1_4 = "rUKPidMihJiyQHedSmumJFTtwtKtA.resources" ascii //weight: 1
        $x_1_5 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 ?? ?? 2e 50 72 6f 70 65 72 74 69 65 73}  //weight: 1, accuracy: Low
        $x_1_6 = "bqocVYTRKxKJWXGLYgkKJhRancbMA.resources" ascii //weight: 1
        $x_1_7 = "RVzywHBbhheccROJrSfRnGjzcJmN.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_MSIL_MassLogger_SA_2147763803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.SA!MTB"
        threat_id = "2147763803"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wHIZWZTOEfkOAFCnOXKnkOwjuoLU.resources" ascii //weight: 1
        $x_1_2 = "scSVKGwfKLrAfdmOeFZNxTgRCEXC" ascii //weight: 1
        $x_1_3 = "PpEEfOBWMpjlWiEKhEwIbWlpHwTr.resources" ascii //weight: 1
        $x_1_4 = "YlAAwjFkQdxcLRhMugHSJoqFKqKv" ascii //weight: 1
        $x_1_5 = "Lime_Pony.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_RDA_2147912634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.RDA!MTB"
        threat_id = "2147912634"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 07 13 05 11 05 6f 80 00 00 0a 13 06 73 81 00 00 0a 0d 09 11 06 17}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_RDB_2147919302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.RDB!MTB"
        threat_id = "2147919302"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 04 06 16 06 8e 69 6f 1c 00 00 0a 09 6f 1d 00 00 0a 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_AML_2147920453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.AML!MTB"
        threat_id = "2147920453"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FroggSecurityChecker.FroggAbout.resources" ascii //weight: 1
        $x_1_2 = "13f38eaa-447e-4059-8dbb-ab215d6a0eaa" ascii //weight: 1
        $x_2_3 = "powered by admin@frogg.fr" wide //weight: 2
        $x_2_4 = "Frogg Security Checker" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_MBXU_2147920462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.MBXU!MTB"
        threat_id = "2147920462"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "CreateInstance" wide //weight: 5
        $x_4_2 = "DeveloperTools.QuickForms" wide //weight: 4
        $x_3_3 = "Split" ascii //weight: 3
        $x_2_4 = "GetPixel" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_MBXT_2147921331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.MBXT!MTB"
        threat_id = "2147921331"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "CSE101_Final_Prep" wide //weight: 5
        $x_4_2 = {4c 00 6f 00 61 00 64}  //weight: 4, accuracy: High
        $x_3_3 = "Calculadora" wide //weight: 3
        $x_2_4 = "InvokeMember" ascii //weight: 2
        $x_1_5 = "Split" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

