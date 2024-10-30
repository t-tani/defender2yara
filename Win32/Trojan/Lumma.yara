rule Trojan_Win32_Lumma_RDA_2147891693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lumma.RDA!MTB"
        threat_id = "2147891693"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lumma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 c8 31 d2 f7 f6 0f b6 44 0d 00 32 04 17 88 44 0d 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lumma_RZ_2147912859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lumma.RZ!MTB"
        threat_id = "2147912859"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lumma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {04 4e 34 70 2c 65 34 22 2c 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lumma_MBXV_2147923463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lumma.MBXV!MTB"
        threat_id = "2147923463"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lumma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {57 89 5c 24 44 33 c9 8b c1 88 4c 0c 4c 99 f7 bc 24 ?? ?? 00 00 8a 04 32 88 84 0c ?? ?? 00 00 41 3b cd 7c e3}  //weight: 2, accuracy: Low
        $x_1_2 = {5a 38 31 78 62 79 75 41 75 61 00 00 51 77 72 75 78 41 41}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lumma_ZZAA_2147924044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lumma.ZZAA!MTB"
        threat_id = "2147924044"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lumma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {57 89 5c 24 ?? 33 c9 33 d2 88 4c 0c ?? 6a 27 8b c1 5f f7 f7 8a 04 32 88 84 0c ?? ?? 00 00 41 3b cd 7c e4}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lumma_AZBA_2147924861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lumma.AZBA!MTB"
        threat_id = "2147924861"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lumma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b c7 74 0f 8b 44 24 ?? 8b 4c 24 ?? 8a 44 04 ?? 30 04 29 85 f6 74}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lumma_AECA_2147925004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lumma.AECA!MTB"
        threat_id = "2147925004"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lumma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b c6 74 13 8b 44 24 ?? 8b 4c 24 ?? 8b 54 24 ?? 8a 44 04 ?? 30 04 0a 83 7f 04 00 0f 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

