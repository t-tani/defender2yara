rule Trojan_Win64_Latrodectus_PA_2147904850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.PA!MTB"
        threat_id = "2147904850"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 99 8b 8c 24 ?? ?? ?? ?? f7 f9 48 98 48 8d 44 04 ?? 48 8b 8c 24 ?? ?? ?? ?? 0f b6 04 08 8b 8c 24 ?? ?? ?? ?? 33 c8 8b c1 48 63 4c 24 ?? 48 8b 54 24 ?? 88 04 0a e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_PB_2147904851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.PB!MTB"
        threat_id = "2147904851"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 01 00 00 00 48 6b d2 2a 0f be 94 14 ?? ?? ?? ?? 0f af ca 48 63 c9 48 2b c1 0f b6 44 04 ?? 8b 8c 24 ?? ?? ?? ?? 33 c8 8b c1 48 63 4c 24 ?? 48 8b 54 24 ?? 88 04 0a e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_PC_2147904945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.PC!MTB"
        threat_id = "2147904945"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 02 8d 44 08 ?? 0f b7 4c 24 ?? 48 8b 54 24 ?? 88 04 0a 0f b6 44 24 ?? 0f b6 4c 24 ?? 33 c1 0f b7 4c 24 ?? 48 8b 54 24 ?? 88 04 0a e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_DA_2147905658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.DA!MTB"
        threat_id = "2147905658"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 4b 7c 8b 43 64 35 23 31 01 00 c1 ea 10 29 43 18 48 8b 05 ?? ?? ?? ?? 88 14 01 41 8b d0 ff 43 7c 48 8b 05 ?? ?? ?? ?? c1 ea 08 48 63 48 7c 48 8b 80 a0 00 00 00 88 14 01}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 c8 48 f7 e2 48 c1 ea 02 48 89 d0 48 c1 e0 02 48 01 d0 48 01 c0 48 01 d0 48 01 c0 48 29 c1 48 89 ca 0f b6 84 15 ?? ?? ?? ?? 44 31 c8 41 88 00 48 83 85 ?? ?? ?? ?? 01 48 8b 85 ?? ?? ?? ?? 48 39 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Latrodectus_DB_2147908540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.DB!MTB"
        threat_id = "2147908540"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 03 cc 48 f7 e1 48 c1 ea 04 48 8d 04 d2 48 ?? c0 48 ?? c8 48 ?? cb 8a 44 0c ?? 43 32 04 13 41 88 02 4d 03 d4 45 3b cd 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_DY_2147908767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.DY!MTB"
        threat_id = "2147908767"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 63 c9 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 45 03 cc 48 f7 e1 48 c1 ea 04 48 6b c2 13 48 2b c8 48 2b cb 8a 44 0c 20 43 32 04 ?? 41 88 02 4d 03 d4 45 3b cd 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_PD_2147910582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.PD!MTB"
        threat_id = "2147910582"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 c8 49 8b c4 48 f7 e1 48 8b c1 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 04 48 6b c0 19 48 2b c8 49 2b cd 0f b6 44 0c ?? 43 32 44 0a ?? 41 88 41 ?? 41 8d 47 ?? 48 63 c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_PE_2147910693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.PE!MTB"
        threat_id = "2147910693"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 c8 49 8b c4 48 f7 e1 48 c1 ea 04 48 6b c2 11 48 2b c8 49 2b cb 0f b6 44 0c ?? 42 32 44 0b ?? 41 88 41 ?? 41 8d 42 ?? 48 63 c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_PF_2147910694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.PF!MTB"
        threat_id = "2147910694"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 98 48 29 c2 8b 85 ?? ?? ?? ?? 48 98 48 01 c2 8b 85 ?? ?? ?? ?? 48 98 48 29 c2 8b 85 ?? ?? ?? ?? 0f af 85 ?? ?? ?? ?? 48 98 48 01 d0 0f b6 84 05 ?? ?? ?? ?? 44 31 c8 41 88 00 48 8b 85 ?? ?? ?? ?? 48 83 c0 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_PG_2147914223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.PG!MTB"
        threat_id = "2147914223"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 63 ca 49 8b c7 41 ff c2 4d 8d 49 ?? 48 f7 e1 48 c1 ea ?? 48 6b c2 ?? 48 2b c8 49 2b cb 0f b6 44 0c ?? 42 32 44 0b ?? 41 88 41 ?? 41 81 fa ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_MA_2147914271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.MA!MTB"
        threat_id = "2147914271"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 2b c8 48 2b cb 0f b6 44 0c ?? 43 32 44 0b ?? 41 88 41 ?? 41 81 fa ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

