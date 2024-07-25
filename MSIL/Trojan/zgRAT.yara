rule Trojan_MSIL_zgRAT_A_2147838647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.A!MTB"
        threat_id = "2147838647"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 0a 0b 06 16 73 ?? 00 00 0a 73 ?? 00 00 0a 0c 08 07 6f ?? 00 00 0a 07 6f ?? 00 00 0a 0d de}  //weight: 2, accuracy: Low
        $x_1_2 = "GetDomain" ascii //weight: 1
        $x_1_3 = "WindowsFormsApp1.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_RDA_2147840146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.RDA!MTB"
        threat_id = "2147840146"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "27a3d4c2-fe45-4455-b52e-7b6ba402e723" ascii //weight: 1
        $x_1_2 = "kernel32" ascii //weight: 1
        $x_1_3 = "LoadLibrary" ascii //weight: 1
        $x_1_4 = "GetProcAddress" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "CreateDecryptor" ascii //weight: 1
        $x_1_7 = "GZipStream" ascii //weight: 1
        $x_1_8 = "Bimzjn" ascii //weight: 1
        $x_1_9 = "IO7cNQtfltKTA5vxNa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_RDB_2147844306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.RDB!MTB"
        threat_id = "2147844306"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Pjlfesrqojyjtuhktzbeswp" ascii //weight: 1
        $x_1_2 = "0e2f6a3564e943bb733f2bef90a3e661" ascii //weight: 1
        $x_1_3 = "31d1d6b6e5054e186a2a953670c99637" ascii //weight: 1
        $x_1_4 = "ff8d14f7abe24bc49c5fec7752fbba52" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_ABSA_2147846497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.ABSA!MTB"
        threat_id = "2147846497"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0c 08 07 6f ?? 00 00 0a 16 73 ?? 00 00 0a 0d 06 8e 69 8d ?? 00 00 01 13 04 09 11 04 16 11 04 8e 69 6f ?? 00 00 0a 26 11 04 28 ?? 00 00 06 26 73 ?? 00 00 06 17 6f ?? 00 00 06 7e ?? 00 00 04 6f ?? 00 00 06 de 14 09 2c 06 09 6f ?? 00 00 0a dc}  //weight: 5, accuracy: Low
        $x_1_2 = "_007Stub.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_B_2147847022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.B!MTB"
        threat_id = "2147847022"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "BHHbH87.g.resources" ascii //weight: 2
        $x_2_2 = "BHHbH87.pdb" ascii //weight: 2
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_NEAA_2147847436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.NEAA!MTB"
        threat_id = "2147847436"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "dee9df0e-b31c-4e88-9cd1-ef8f591360d4" ascii //weight: 2
        $x_2_2 = "HHhHh76.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_C_2147848523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.C!MTB"
        threat_id = "2147848523"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 00 01 00 00 14 14 11 06 74}  //weight: 2, accuracy: High
        $x_2_2 = "NBNNhH873.g.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_E_2147850697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.E!MTB"
        threat_id = "2147850697"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 0a 0d 08 73 ?? 00 00 0a 13 04 11 04 07 16 73 ?? 00 00 0a 13 05 11 05 09 6f ?? 00 00 0a 09 6f ?? 00 00 0a 13 06 de}  //weight: 2, accuracy: Low
        $x_1_2 = "GetTypes" ascii //weight: 1
        $x_1_3 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_F_2147895010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.F!MTB"
        threat_id = "2147895010"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 1f 10 11 04 16 03 8e 69 1f 10 da 28}  //weight: 2, accuracy: High
        $x_2_2 = {11 09 11 04 16 11 04 8e 69 6f ?? 00 00 0a 13 07}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_G_2147895225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.G!MTB"
        threat_id = "2147895225"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 08 06 91 20 ?? ?? ?? 28 28 ?? 00 00 06 28 ?? 00 00 0a 59 d2 9c 06 17 58 0a 06 08 8e 69}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_H_2147895605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.H!MTB"
        threat_id = "2147895605"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 0a 13 07 73 ?? ?? 00 0a 13 05 11 06 73 ?? ?? 00 0a 0c 08 11 07 16 73 ?? ?? 00 0a 0d 09 11 05 6f ?? ?? 00 0a 11 05 6f ?? ?? 00 0a 13 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_I_2147895662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.I!MTB"
        threat_id = "2147895662"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 13 06}  //weight: 2, accuracy: Low
        $x_2_2 = {09 11 05 16 11 05 8e 69 6f ?? 00 00 0a 08 6f ?? 00 00 0a 13 07}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_J_2147896546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.J!MTB"
        threat_id = "2147896546"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 70 20 00 01 00 00 14 14 14 6f 14 00 06 13 ?? 72 ?? 00 00 70 28 ?? 00 00 06 11 ?? 8e 69 26 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_K_2147897162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.K!MTB"
        threat_id = "2147897162"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 11 05 08 11 05 91 11 04 11 05 11 04 6f ?? ?? 00 0a 5d 6f ?? ?? 00 0a 61 d2 9c 11 05 17 58 13 05 11 05 08 8e 69}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_L_2147897163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.L!MTB"
        threat_id = "2147897163"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 11 04 08 11 04 91 20 ?? ?? 00 00 28 ?? ?? 00 06 11 04 20 ?? ?? 00 00 28 ?? ?? 00 06 28 ?? ?? 00 0a 5d 28 ?? ?? 00 0a 61 d2 9c 11 04 17 58 13 04 11 04 08 8e 69}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_L_2147897163_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.L!MTB"
        threat_id = "2147897163"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {91 61 d2 9c 0e 00 02 11 ?? 02 11 ?? 91 03 11 ?? 03 8e 69 5d}  //weight: 2, accuracy: Low
        $x_2_2 = {16 1f 20 9d 11 ?? 6f ?? 00 00 0a 13 ?? 20 0d 00 02 16 9a 17 8d ?? 00 00 01 13 ?? 11}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_M_2147897177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.M!MTB"
        threat_id = "2147897177"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 08 06 91 20 ?? ?? ?? a1 28 ?? ?? 00 06 06 19 5d 28 ?? ?? 00 0a 61 d2 9c 06 16 2d ?? 17 58 0a 06 08 8e 69}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_N_2147897319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.N!MTB"
        threat_id = "2147897319"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 11 04 08 11 04 91 72 ?? ?? 00 70 11 04 72 ?? ?? 00 70 28 ?? ?? 00 0a 5d 28 ?? ?? 00 0a 61 d2 9c 11 04 17 58 13 04 11 04 08 8e 69}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_O_2147898079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.O!MTB"
        threat_id = "2147898079"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 06 20 00 01 00 00 14 14 14 6f ?? 00 00 0a 26 20}  //weight: 2, accuracy: Low
        $x_1_2 = "Reverse" ascii //weight: 1
        $x_1_3 = "GZipStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_P_2147898080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.P!MTB"
        threat_id = "2147898080"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 06 20 00 01 00 00 14 14 14 6f ?? 01 00 0a 2a}  //weight: 2, accuracy: Low
        $x_1_2 = "Reverse" ascii //weight: 1
        $x_1_3 = "GetTypes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_MBFN_2147898427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.MBFN!MTB"
        threat_id = "2147898427"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 07 07 1f 16 5d 91 13 0e 11 0d 11 0e 61 13 0f 11 0f 11 0c 59 13 10 08 11 06 11 10 11 05 5d d2 9c 07 17 58 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_KAC_2147900003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.KAC!MTB"
        threat_id = "2147900003"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 50 11 02 8f ?? 00 00 01 25 71 ?? 00 00 01 1f 58 61 d2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_R_2147900447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.R!MTB"
        threat_id = "2147900447"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 0a dc 07 28 ?? 00 00 2b 28 ?? 00 00 2b 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 2b 72 ?? 00 00 70 20 00 01 00 00 14 14 14 6f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_S_2147900539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.S!MTB"
        threat_id = "2147900539"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 25 16 72 ?? 00 00 70 a2 25 18 20 ?? ?? 00 00 8c ?? 00 00 01 a2 25 19 28 ?? ?? 00 0a a2 25 1a 20 ?? ?? 00 00 8c ?? 00 00 01 a2 25 1b 20 ?? ?? ?? 00 28 ?? ?? 00 06 a2 25 1c 02 7b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_RDC_2147900570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.RDC!MTB"
        threat_id = "2147900570"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 09 11 03 16 11 03 8e 69 6f 97 00 00 0a 13 06}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_T_2147900943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.T!MTB"
        threat_id = "2147900943"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 04 20 00 01 00 00 0e 04 50 74 ?? 00 00 01 0e 04 50 28 ?? 00 00 0a 28 ?? ?? 00 06 05 6f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_T_2147900943_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.T!MTB"
        threat_id = "2147900943"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 07 18 5a 58 0a 38 ?? 00 00 00 06 07 19 5a 58 0a 38 ?? 00 00 00 06 07 1a 5a 58 0a 07 17 58}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_RDD_2147901621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.RDD!MTB"
        threat_id = "2147901621"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0d 09 28 01 00 00 2b 28 02 00 00 2b 0d 16}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_U_2147901991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.U!MTB"
        threat_id = "2147901991"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 25 16 72 ?? 00 00 70 a2 25 18 20 ?? ?? 00 00 8c ?? 00 00 01 a2 25 19 28 ?? ?? 00 06 a2 25 1a 20 ?? ?? 00 00 8c ?? 00 00 01 a2 25 1b 20 ?? ?? ?? 00 28 ?? ?? 00 06 a2 25 1c 02 7b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_V_2147902190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.V!MTB"
        threat_id = "2147902190"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 00 06 d0 36 00 00 02 28 ?? 01 00 06 6f ?? 00 00 0a 73 ?? 00 00 0a 80 61 00 00 04 20}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_W_2147902982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.W!MTB"
        threat_id = "2147902982"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 25 16 72 ?? 00 00 70 a2 25 18 20 ?? ?? 00 00 8c ?? 00 00 01 a2 25 19 7e ?? ?? 00 04 28 ?? ?? 00 06 a2 25 1a 20 ?? ?? 00 00 8c ?? 00 00 01 a2 25 1b 20 ?? ?? 00 00 28 ?? 00 00 06 a2 25 1c 02 7b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_NA_2147903270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.NA!MTB"
        threat_id = "2147903270"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {61 19 11 1b 58 61 11 ?? 61 d2 9c 20}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_Y_2147903995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.Y!MTB"
        threat_id = "2147903995"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 00 04 00 00 8d ?? 00 00 01 13 01 20}  //weight: 2, accuracy: Low
        $x_2_2 = {0a 14 14 6f ?? 00 00 0a 26 20}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_NB_2147905149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.NB!MTB"
        threat_id = "2147905149"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 27 11 20 61 19 11 1d 58 61 11 32 61 d2 9c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_Z_2147905636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.Z!MTB"
        threat_id = "2147905636"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {04 07 16 6f ?? 00 00 0a 0c 12 ?? 28 ?? 00 00 0a 0d 06 07 09 9c 07 17 58 0b 07 02}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_AE_2147905971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.AE!MTB"
        threat_id = "2147905971"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4b 00 61 00 45 00 6f 00 01 15 49 00 21 00 6f 00 5b 00 58 00 3b 00 67 00 45 00 5c 00 39 00 00 15 49 00 21 00 6d 00 53 00 72 00 61 00 61 00 26 00 32 00 5a 00 00 15 49 00 21 00 6f 00 73 00 60 00 4b 00 36 00 5f 00 63 00 69 00 00 15 49 00 21 00 6f 00 6d}  //weight: 1, accuracy: High
        $x_1_2 = {49 00 21 00 6d 00 66 00 23 00 6f 00 51 00 62 00 62 00 30 00 00 15 49 00 21 00 70 00 3c 00 6a 00 46 00 2a 00 57 00 28 00 59 00 00 15 49 00 21 00 70 00 2d 00 65 00 4d 00 67 00 39 00 56 00 71 00 01 15 49 00 21 00 6d 00 4d 00 70 00 38 00 39 00 6f 00 4e}  //weight: 1, accuracy: High
        $x_2_3 = "bb16ec941e714ae3d2b837c89603471b" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_AA_2147906016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.AA!MTB"
        threat_id = "2147906016"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 02 11 03 11 01 11 03 91 72 ?? 00 00 70 28 ?? 00 00 06 59 d2 9c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_AB_2147909345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.AB!MTB"
        threat_id = "2147909345"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 8e 69 1f 10 da 11 02 16 1f 10 28}  //weight: 2, accuracy: High
        $x_2_2 = {02 16 11 0a 16 02 8e 69 1f 10 da 28}  //weight: 2, accuracy: High
        $x_2_3 = {02 8e 69 1f 11 da 17 d6 8d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_NZ_2147914989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.NZ!MTB"
        threat_id = "2147914989"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {ff 11 02 6f ?? 00 00 0a 28 ?? 00 00 2b 6f ?? 00 00 0a 13 0d 20 17 00 00 00 38 70 fd ff ff 11 0a 18 5d 3a ?? ff ff ff 20 ?? 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 39 ?? fd ff ff 26}  //weight: 4, accuracy: Low
        $x_1_2 = "OpenPop.Properties" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

