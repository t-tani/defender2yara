rule Trojan_Win64_Tedy_GHN_2147845256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.GHN!MTB"
        threat_id = "2147845256"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {45 89 f4 41 c0 fc 02 45 00 ec 83 c5 02 46 88 24 38 41 89 ef 0f b6 6c 24 67 40 80 fd 40 74 11 41 c0 e6 06 44 00 f5 4d 63 f7 41 ff c7 42 88 2c 30 45 31 ed e9}  //weight: 10, accuracy: High
        $x_1_2 = "NTI3NTZlNDE3Mw==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_FG_2147848041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.FG!MTB"
        threat_id = "2147848041"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 63 84 24 a8 00 00 00 0f b6 84 04 98 04 00 00 8b 8c 24 10 01 00 00 c1 e1 03 48 8b 94 24 a0 04 00 00 48 d3 ea 48 8b ca 0f b6 c9 33 c1 48 63 8c 24 a8 00 00 00 88 84 0c a0 67 00 00 eb 87}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_SPS_2147850797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.SPS!MTB"
        threat_id = "2147850797"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4c 8d 8d 68 01 00 00 45 33 c0 b2 01 8b cb e8 ?? ?? ?? ?? ff c3 83 fb 24 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_QC_2147851552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.QC!MTB"
        threat_id = "2147851552"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 48 8b 04 25 60 00 00 00 44 8b d3 41 be bf e5 f1 78 48 8b 50 18 48 83 c2 10 48 8b 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_SPK_2147852473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.SPK!MTB"
        threat_id = "2147852473"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f 11 84 24 c0 00 00 00 0f 11 44 24 50 f2 0f 10 05 ?? ?? ?? ?? f2 0f 11 84 24 f0 00 00 00 0f 10 05 ?? ?? ?? ?? 0f 11 8c 24 e0 00 00 00 0f 10 0d ?? ?? ?? ?? 0f 11 84 24 00 01 00 00 0f 10 05 ?? ?? ?? ?? 0f 11 8c 24 10 01 00 00 0f 11 84 24 20 01 00 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_GPB_2147891569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.GPB!MTB"
        threat_id = "2147891569"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {49 89 d8 4c 89 f2 48 89 f9 48 83 c7 02 e8 7e ff ff ff 48 89 f0 31 d2 48 83 c6 01 48 f7 f5 41 0f b6 04 14 30 03 48 83 c3 01 49 39 f5 75 d2}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_PABC_2147892091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.PABC!MTB"
        threat_id = "2147892091"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 44 24 68 59 00 66 4d c7 44 24 6c 53 54 5e 55 c7 44 24 70 4d 49 66 49 c7 44 24 74 43 49 4e 5f c7 44 24 78 57 09 08 66 c7 44 24 7c 54 4e 5e 56 c7 45 80 56 14 5e 56 66 c7 45 84 56 3a c7 45 c8 43 72 65 61 c7 45 cc 74 65 46 69 c7 45 d0 6c 65 4d 61 c7 45 d4 70 70 69 6e 66 c7 45 d8 67 41 c6 45 da 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_NTD_2147895927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.NTD!MTB"
        threat_id = "2147895927"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 63 c3 48 03 c0 49 83 24 c4 00 33 c0 eb db 48 89 5c 24 ?? 48 89 6c 24 ?? 48 89 74 24 ?? 57 48 83 ec 20 bf ?? ?? ?? ?? 48 8d 1d 60 f5 0a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_NTD_2147895927_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.NTD!MTB"
        threat_id = "2147895927"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f 84 23 01 00 00 85 c9 75 4a c7 05 9f 9d 01 00 ?? ?? ?? ?? 48 8d 15 e0 f0 00 00 48 8d 0d a1 f0 00 00 e8 44 4a}  //weight: 5, accuracy: Low
        $x_1_2 = "://ftp.2qk.cn/HD1-2.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_NTD_2147895927_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.NTD!MTB"
        threat_id = "2147895927"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pod paczke BlazingPack" ascii //weight: 1
        $x_1_2 = "bledna licencja lub jestes zjebany" ascii //weight: 1
        $x_1_3 = "villadentex.pl" ascii //weight: 1
        $x_1_4 = "Classes loaded succesfuly" ascii //weight: 1
        $x_1_5 = "pod paczke Lunar Client" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_RB_2147897550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.RB!MTB"
        threat_id = "2147897550"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6c 24 38 48 8d 6c 24 38 48 b8 ba 06 e2 3b 5d 04}  //weight: 1, accuracy: High
        $x_1_2 = "ibhchocjdb/kfapioijci/fjfkdpkdco/fjfkdpkdco/kbpchiokil.Egcgaefamc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_EM_2147898412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.EM!MTB"
        threat_id = "2147898412"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {30 84 0d 18 05 00 00 48 ff c1 48 83 f9 25 72 ed}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_NT_2147899511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.NT!MTB"
        threat_id = "2147899511"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {e8 2e 62 00 00 44 8b cb 4c 8b c0 33 d2 48 8d 0d ?? ?? ?? ?? e8 aa e8 ff ff}  //weight: 3, accuracy: Low
        $x_3_2 = {e8 0a 31 00 00 e8 0d 31 00 00 48 8d 2d ?? ?? ?? ?? 48 8d 15 55 00 02 00 41 b8 00 10 00 00 48 89 e9}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_NT_2147899511_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.NT!MTB"
        threat_id = "2147899511"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HusClass" ascii //weight: 1
        $x_1_2 = "Key doesnt exist !" ascii //weight: 1
        $x_1_3 = "TTRs Internal Slotted" ascii //weight: 1
        $x_1_4 = "WORK ONLY ON EAC" ascii //weight: 1
        $x_1_5 = "vvsk2nJWPd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_NT_2147899511_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.NT!MTB"
        threat_id = "2147899511"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {74 12 45 33 c0 41 8d 50 ?? 33 c9 48 8b 03 ff 15 d1 2f 00 00 e8 f8 06 00 00 48 8b d8 48 83 38 ?? 74 14 48 8b c8}  //weight: 5, accuracy: Low
        $x_1_2 = "Fix Fake Damage" ascii //weight: 1
        $x_1_3 = "CARLOS CHEAT" ascii //weight: 1
        $x_1_4 = "AARYAN V4X - Sniper Panel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_AMBE_2147903244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.AMBE!MTB"
        threat_id = "2147903244"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 63 c8 49 8b c7 48 f7 e1 48 c1 ea 05 48 8d 04 d2 48 c1 e0 02 48 2b c8 42 0f b6 04 21 88 04 1e 48 ff c6 48 83 fe}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_GPAA_2147905958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.GPAA!MTB"
        threat_id = "2147905958"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {0f b6 4c 14 56 31 c8 0f b6 d8 48 8d 44 24 2c}  //weight: 3, accuracy: High
        $x_1_2 = "de_xor" ascii //weight: 1
        $x_1_3 = "de_Rc4" ascii //weight: 1
        $x_1_4 = "de_Aes" ascii //weight: 1
        $x_1_5 = "de_AesRc4Xor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_SGA_2147906771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.SGA!MTB"
        threat_id = "2147906771"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RegFlushKey" ascii //weight: 1
        $x_1_2 = "com.embarcadero.lsasse" wide //weight: 1
        $x_1_3 = "DLLFILE" wide //weight: 1
        $x_1_4 = "logd64" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_SMD_2147907280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.SMD!MTB"
        threat_id = "2147907280"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e9 c1 fa 04 8b c2 c1 e8 ?? 03 d0 0f be c2 6b d0 31 0f b6 c1 ff c1 2a c2 04 39 41 30 40 ff 83 f9 04 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_HNA_2147908379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.HNA!MTB"
        threat_id = "2147908379"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 ff ff ff ff 48 8b b4 24 c0 04 00 00 48 8b 9c 24 b0 04 00 00 48 8b bc 24 a0 04 00 00 48 8b 8c 24 90 04 00 00 48 33 cc}  //weight: 1, accuracy: High
        $x_1_2 = {48 c7 44 24 30 00 00 00 00 4c 8b cf c7 44 24 28 00 00 00 00 45 33 c0 33 d2 48 89 74 24 20 48 8b cb}  //weight: 1, accuracy: High
        $x_1_3 = {4f 70 65 6e 50 72 6f 63 65 73 73 [0-4] 43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 [0-4] 50 72 6f 63 65 73 73 33 32 4e 65 78 74 57 [0-4] 50 72 6f 63 65 73 73 33 32 46 69 72 73 74 57 [0-4] 47 65 74 50 72 6f 63 41 64 64 72 65 73 73 [0-4] 56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 [0-4] 43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_RM_2147909344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.RM!MTB"
        threat_id = "2147909344"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 2b d0 8b 42 fc d3 e8 49 89 51 08 41 89 41 18 0f b6 0a 83 e1 0f 4a 0f be 84 11 e8 d7 02 00 42 8a 8c 11 f8 d7 02 00 48 2b d0 8b 42 fc d3 e8 49 89 51 08 41 89 41 1c 0f b6 0a 83 e1 0f 4a 0f be 84 11 e8 d7 02 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 20 00 74 00 72 00 61 00 6e 00 73 00 6c 00 61 00 74 00 65 00 20 00 6d 00 61 00 73 00 74 00 65 00 72 00 5c 00 [0-16] 57 00 72 00 61 00 70 00 70 00 65 00 72 00 5c 00 78 00 36 00 34 00}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 47 6f 6f 67 6c 65 20 74 72 61 6e 73 6c 61 74 65 20 6d 61 73 74 65 72 5c [0-16] 57 72 61 70 70 65 72 5c 78 36 34}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_Tedy_RS_2147909972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.RS!MTB"
        threat_id = "2147909972"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 84 24 00 01 00 00 48 63 40 3c 48 8b 4c 24 48 48 03 c8 48 8b c1 48 63 4c 24 6c 48 6b c9 28 48 8d 84 08 08 01 00 00 48 89 84 24 98 00 00 00 48 8b 84 24 98 00 00 00 8b 40 14 48 8b 8c 24 98 00 00 00 8b 49 10 48 03 c1 48 89 84 24 c8 01 00 00 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_ATY_2147911512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.ATY!MTB"
        threat_id = "2147911512"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 89 ca 41 8d 0c 18 42 32 4c 00 10 48 c1 fa 08 31 d1 4c 89 ca 49 c1 f9 18 48 c1 fa 10 31 d1 44 31 c9 42 88 4c 00 10 49 ff c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_ATY_2147911512_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.ATY!MTB"
        threat_id = "2147911512"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c8 05 88 43 40 48 85 d2 0f 84 54 01 00 00 48 83 7a 18 00 0f 84 39 01 00 00 48 8b 42 18 f0 83 00 01 48 8b 4b 30 48 85 c9 74 06 ff 15 c8 7d 01 00 4c 89 e9 e8 24 1d 00 00 48 8b 4b 28 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_ATY_2147911512_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.ATY!MTB"
        threat_id = "2147911512"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 45 e0 88 85 f0 14 00 00 0f 28 45 c0 0f 28 4d d0 0f 29 8d e0 14 00 00 0f 29 85 d0 14 00 00 31 c9 31 d2 49 89 f8 ff 15 14 49 01 00}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b d7 4c 8b 4d c7 4b 8b 8c cb 20 32 05 00 48 03 ca 8a 04 32 42 88 44 f9 3e ff c7 48 ff c2 48 63 c7}  //weight: 1, accuracy: High
        $x_1_3 = {49 2b f6 4b 8b 8c eb 20 32 05 00 49 03 ce 42 8a 04 36 42 88 44 f9 3e ff c7 49 ff c6 48 63 c7 48 3b c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_GPBX_2147912805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.GPBX!MTB"
        threat_id = "2147912805"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "taskkill /IM ProcessHacker.exe /F" ascii //weight: 1
        $x_1_2 = "taskkill /IM dnSpy.exe /F" ascii //weight: 1
        $x_1_3 = "taskkill /IM cheatengine-x86_64.exe /F" ascii //weight: 1
        $x_1_4 = "taskkill /IM ollydbg.exe /F" ascii //weight: 1
        $x_1_5 = "taskkill /IM ida64.exe /F" ascii //weight: 1
        $x_1_6 = "taskkill /IM x64dbg.exe /F" ascii //weight: 1
        $x_1_7 = "Stop debugging" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_ATE_2147912968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.ATE!MTB"
        threat_id = "2147912968"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 0f b6 08 49 83 c0 01 31 d9 c1 eb 08 0f b6 c9 33 1c 8a 4c 39 c6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_ZQ_2147913604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.ZQ!MTB"
        threat_id = "2147913604"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 33 ?? 31 f8 88 44 33 ?? 48 89 fa 48 c1 fa ?? 31 d0 48 89 fa 48 c1 fa ?? 31 d0 48 89 fa 48 83 c7 ?? 48 c1 fa ?? 31 d0 88 44 33}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_ZW_2147913634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.ZW!MTB"
        threat_id = "2147913634"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f3 0f 6f e2 66 0f 61 d3 66 41 0f db c8 66 0f 69 e3 66 0f 61 d4 66 41 0f db d0 66 0f 67 ca 66 0f ef c8 0f 11}  //weight: 1, accuracy: High
        $x_1_2 = {41 32 54 04 ?? 49 c1 f9 ?? 31 ca 48 c1 f9 ?? 44 31 ca 31 ca 41 88 54 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_ZX_2147913649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.ZX!MTB"
        threat_id = "2147913649"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {32 54 03 10 48 c1 f9 10 31 f2 31 ca 48 89 f1 48 c1 f9 18 31 ca 48 8d 4e 01 88 54 03 10}  //weight: 1, accuracy: High
        $x_1_2 = "static/loader_client_no_literals_compression.bin" ascii //weight: 1
        $x_1_3 = "dXNlcjpRd2VydHkxMjMh" ascii //weight: 1
        $x_1_4 = "updater.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_DA_2147914003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.DA!MTB"
        threat_id = "2147914003"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 00 48 8d 0d ?? ?? ?? ?? 48 8b 54 24 08 0f b6 0c 11 2b c1 05 00 01 00 00 99 81 e2 ff 00 00 00 03 c2 25 ff 00 00 00 2b c2 48 8b 0c 24 48 8b 54 24 28 48 03 d1 48 8b ca 88 01 48 8b 44 24 08 48 ff c0 33 d2 b9 08 00 00 00 48 f7 f1 48 8b c2 48 89 44 24 08 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_DA_2147914003_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.DA!MTB"
        threat_id = "2147914003"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\\\.\\VBoxMiniRdrDN" ascii //weight: 10
        $x_10_2 = "FortniteClient-Win64-Shipping.exe" ascii //weight: 10
        $x_1_3 = "D3D11CreateDeviceAndSwapChain" ascii //weight: 1
        $x_1_4 = "d3d11.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_GP_2147914911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.GP!MTB"
        threat_id = "2147914911"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 41 aa 30 44 0d a8 48 ff c1 48 83 f9 30 72 f0 c6 45 d9 00 4c 89 7c 24 48 4c 89 7c 24 58 48 c7 44 24 60 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_GPJ_2147914912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.GPJ!MTB"
        threat_id = "2147914912"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "cdn.discordapp.com/attachments/1223133498550911067/1231358676225359932/svhost.exe" ascii //weight: 5
        $x_1_2 = "cdn.discordapp.com/attachments" ascii //weight: 1
        $x_1_3 = "ces.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_MD_2147915202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.MD!MTB"
        threat_id = "2147915202"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TestMalvare.pdb" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "DisableRealtimeMonitoring" wide //weight: 1
        $x_1_4 = "DisableTaskMgr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_NAA_2147915616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.NAA!MTB"
        threat_id = "2147915616"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Musquitao\\Desktop\\BR_2023\\LOAD_2023\\DLL-CPP\\D\\x64\\Release\\D.pdb" ascii //weight: 5
        $x_1_2 = "\\Documents" ascii //weight: 1
        $x_1_3 = "SeShutdownPrivilege" ascii //weight: 1
        $x_1_4 = "D.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_RF_2147916602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.RF!MTB"
        threat_id = "2147916602"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 73 01 0f 1f 40 00 0f 1f 84 00 00 00 00 00 49 8b 14 de 49 8b c5 66 0f 1f 84 00 00 00 00 00 0f b6 0c 02 48 ff c0 41 3a 4c 04 ff 75 1d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_DKZ_2147920721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.DKZ!MTB"
        threat_id = "2147920721"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8d 50 4f 30 14 08 48 ff c0 48 83 f8 03 72 f1}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_RZ_2147922688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.RZ!MTB"
        threat_id = "2147922688"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "start cmd /C \"color b && title Error && echo" ascii //weight: 1
        $x_1_2 = "certutil -hashfile" ascii //weight: 1
        $x_1_3 = "&& timeout /t 5" ascii //weight: 1
        $x_1_4 = "%s %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x" ascii //weight: 1
        $x_2_5 = {8d 50 7f 30 14 08 48 ff c0 48 83 f8 ?? 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_ARA_2147923215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.ARA!MTB"
        threat_id = "2147923215"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "curl -F \"image=@" ascii //weight: 2
        $x_2_2 = "\\Microsoft\\Windows\\.winSession" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_ARA_2147923215_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.ARA!MTB"
        threat_id = "2147923215"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\Startup\\NVIDIAGraphics.lnk" ascii //weight: 2
        $x_2_2 = "\\Startup\\MicrosoftDefender.lnk" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_ARA_2147923215_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.ARA!MTB"
        threat_id = "2147923215"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set-MpPreference -DisableRealtimeMonitoring $true -DisableScriptScanning $true" ascii //weight: 1
        $x_1_2 = "-DisableBehaviorMonitoring $true -DisableIOAVProtection $true -DisableIntrusionPreventionSystem $true" ascii //weight: 1
        $x_1_3 = "Add-MpPreference -ExclusionPath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

