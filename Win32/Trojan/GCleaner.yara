rule Trojan_Win32_GCleaner_CC_2147848018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GCleaner.CC!MTB"
        threat_id = "2147848018"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GCleaner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6a 0b ff d7 6a 0c 8b d8 ff d7 8b 4e 20 8b f8 8d 44 24 10 50 51 ff 15 68 55 48 00 8b 44 24 1c 2b 44 24 14 8b 56 74 2b c7 40 52 99 2b c2 d1 f8 50 8b 44 24 20 2b 44 24}  //weight: 2, accuracy: High
        $x_2_2 = {e8 96 ed ff ff 85 c0 74 1e 68 f0 c9 49 00 8d 54 24 18 52 8d 44 24 20 50 e8 4e 2a 00 00 83 c4 0c c6 44 24 24 02 eb 1c 68 1c ca 49}  //weight: 2, accuracy: High
        $x_1_3 = {d6 9e 74 0e a5 e4 e6 fc 43 35 7a 0c 6d 20 15 a6 68 37 b3 bb 28 b7 67 62 4e 34 48 61 4b 71 f5 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GCleaner_BJ_2147848233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GCleaner.BJ!MTB"
        threat_id = "2147848233"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GCleaner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {55 8b ec 56 ff 15 1c e5 46 00 8b 75 14 6a 00 6a 00 56 ff 15 ac e4 46 00 56 ff 15 b0 e4 46 00 e9}  //weight: 5, accuracy: High
        $x_5_2 = {55 8b ec 56 ff 15 f8 e4 46 00 8b 75 14 6a 00 6a 00 56 ff 15 90 e4 46 00 56 ff 15 94 e4 46 00 e9}  //weight: 5, accuracy: High
        $x_5_3 = {55 8b ec 56 8b 75 14 56 ff 15 00 b0 46 00 56 e8 e2 26 04 00 e9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_GCleaner_BK_2147848234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GCleaner.BK!MTB"
        threat_id = "2147848234"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GCleaner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 8b 45 14 50 e8 ?? 3b 04 00 e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GCleaner_GJU_2147849238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GCleaner.GJU!MTB"
        threat_id = "2147849238"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GCleaner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 8b ec 83 ec 0c 53 56 57 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 89 45 f8 8b 45 14 50 ff 15 ?? ?? ?? ?? e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GCleaner_BM_2147849582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GCleaner.BM!MTB"
        threat_id = "2147849582"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GCleaner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a 00 e8 [0-4] 8b 45 14 50 ff 15 [0-4] e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GCleaner_BN_2147849583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GCleaner.BN!MTB"
        threat_id = "2147849583"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GCleaner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {55 8b ec 56 68 28 db 46 00 ff 15 e0 b0 46 00 e9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GCleaner_BO_2147849616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GCleaner.BO!MTB"
        threat_id = "2147849616"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GCleaner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {55 8b ec 83 ec 0c 53 56 57 8b 45 14 50 e8 4e 54 04 00 e9}  //weight: 5, accuracy: High
        $x_5_2 = {ec 83 ec 0c 53 56 57 8b 45 14 50 e8 02 54 04 00 e9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_GCleaner_BO_2147849616_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GCleaner.BO!MTB"
        threat_id = "2147849616"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GCleaner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 56 8b 75 14 57 56 e8 [0-4] 6a 19 6a 14 6a 0b 6a 0a 68 [0-4] ff 15 [0-4] e9}  //weight: 5, accuracy: Low
        $x_5_2 = {0c 53 56 57 8b 45 14 50 e8 d2 53 04 00 e9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_GCleaner_CA_2147851283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GCleaner.CA!MTB"
        threat_id = "2147851283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GCleaner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 83 ec 0c 53 56 57 68 34 19 47 00 68 04 01 00 00 ff 15 c0 f2 46 00 e9}  //weight: 5, accuracy: High
        $x_5_2 = {55 8b ec 83 ec 0c 53 56 57 8b 45 14 50 e8 ?? 4d 04 00 e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_GCleaner_AGC_2147905084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GCleaner.AGC!MTB"
        threat_id = "2147905084"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GCleaner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 8b 4e 10 f7 f3 8a 9a ac 9c 43 00 8b 56 14 88 5d f0 3b ca}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GCleaner_AGC_2147905084_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GCleaner.AGC!MTB"
        threat_id = "2147905084"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GCleaner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 01 0f 43 45 bc 6a 00 6a 03 ff 73 40 ff 73 3c 6a 50 50 56 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GCleaner_ASGE_2147912024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GCleaner.ASGE!MTB"
        threat_id = "2147912024"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GCleaner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {33 ed 8b 44 24 ?? 33 4c 24 ?? 03 44 24 ?? 33 c1 c7 05 ?? ?? ?? ?? ee 3d ea f4 81 3d ?? ?? ?? ?? 13 02 00 00 89 4c 24 ?? 89 44 24 ?? 75}  //weight: 4, accuracy: Low
        $x_1_2 = {81 fe 38 71 20 00 7f 09 46 81 fe 72 f6 04 00 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GCleaner_AGN_2147913607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GCleaner.AGN!MTB"
        threat_id = "2147913607"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GCleaner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c0 80 b0 a0 bb 42 00 2e 40 83 f8 0f 72 f3 b9 a0 bb 42 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b ec 83 ec 08 a1 18 a0 42 00 33 c5 89 45 fc 64 a1 2c 00 00 00 c7 45 f8 5a 59 41 2e 8b 08 a1 78 bc 42 00 3b 81}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GCleaner_AGN_2147913607_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GCleaner.AGN!MTB"
        threat_id = "2147913607"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GCleaner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f 28 0d d0 5b 43 00 66 0f ef c8 0f 11 0d 20 ac 43 00 0f 1f 80 00 00 00 00 80 b0 20 ac 43 00 2e 40 83 f8 12}  //weight: 2, accuracy: High
        $x_2_2 = {0f 10 05 04 ac 43 00 b8 10 00 00 00 0f 28 0d d0 5b 43 00 66 0f ef c8 0f 11 0d 04 ac 43 00 80 b0 04 ac 43 00 2e 40 83 f8 1a}  //weight: 2, accuracy: High
        $x_1_3 = "/f & erase" ascii //weight: 1
        $x_1_4 = "/c taskkill /im" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GCleaner_MKV_2147915195_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GCleaner.MKV!MTB"
        threat_id = "2147915195"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GCleaner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 45 70 8b 45 70 03 85 6c fe ff ff 8b 95 88 fe ff ff 03 d6 33 c2 33 c7 2b d8 8b c3 c1 e8 05 c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 70 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GCleaner_AGE_2147915411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GCleaner.AGE!MTB"
        threat_id = "2147915411"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GCleaner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 28 0d b0 98 43 00 66 0f ef c8 0f 11 09 0f 1f 40 00 80 34 08 2e 40 83 f8 1c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GCleaner_AZZ_2147915702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GCleaner.AZZ!MTB"
        threat_id = "2147915702"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GCleaner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 45 70 8b 45 70 8b 8d c8 fe ff ff 03 c7 03 cb 33 c1 33 c6 29 85 c0 fe ff ff 8b 85 c0 fe ff ff c1 e8 05 c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GCleaner_ASGH_2147915768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GCleaner.ASGH!MTB"
        threat_id = "2147915768"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GCleaner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 c6 30 08 83 fb 0f 75}  //weight: 5, accuracy: High
        $x_5_2 = {81 fe 8e 40 00 00 7e 0c 81 bd ?? e3 ff ff d7 be f5 00 75 09 46 81 fe d2 7e 68 00 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GCleaner_BAZ_2147915839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GCleaner.BAZ!MTB"
        threat_id = "2147915839"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GCleaner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 c7 05 14 7b 81 02 ee 3d ea f4 89 45 70 8b 85 70 fe ff ff 01 45 70 8b b5 78 fe ff ff 8b 8d 80 fe ff ff 03 8d 78 fe ff ff c1 e6 04 03 b5 64 fe ff ff 33 f1 81 3d ?? ?? ?? ?? 03 0b 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GCleaner_ROE_2147916144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GCleaner.ROE!MTB"
        threat_id = "2147916144"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GCleaner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 85 f4 fb ff ff 8a 8d f8 fb ff ff 03 c6 30 08 83 fb 0f 75 16 57 8d 85 fc fb ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GCleaner_AMAP_2147916200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GCleaner.AMAP!MTB"
        threat_id = "2147916200"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GCleaner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c6 30 08 83 fb 0f 75 ?? 57 57 57 57 ff 15 ?? ?? ?? ?? 46 3b f3 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GCleaner_BAW_2147916368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GCleaner.BAW!MTB"
        threat_id = "2147916368"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GCleaner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 8a 4d fc 03 c2 30 08 42 3b d6 7c ?? 5f 83 fe 2d 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GCleaner_PAFL_2147919299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GCleaner.PAFL!MTB"
        threat_id = "2147919299"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GCleaner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 f8 83 c0 46 89 45 fc 83 6d fc 0a 83 6d fc 3c 8b 45 08 8a 4d fc 03 c7 30 08 47 3b fb 7c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GCleaner_MFT_2147919647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GCleaner.MFT!MTB"
        threat_id = "2147919647"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GCleaner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {56 83 65 fc 00 8d 75 fc e8 ?? ?? ?? ?? 8b 45 08 8a 4d fc 30 0c 38 47 3b fb 7c}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GCleaner_MFB_2147919740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GCleaner.MFB!MTB"
        threat_id = "2147919740"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GCleaner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8d 14 07 8b 44 24 18 c1 e8 05 89 44 24 10 8b 44 24 10 33 ca 03 c5 33 c1 81 3d ?? ?? ?? ?? 13 02 00 00 c7 05 ?? ?? ?? ?? ee 3d ea f4 89 44 24 10 0f 85}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GCleaner_MFC_2147919821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GCleaner.MFC!MTB"
        threat_id = "2147919821"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GCleaner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {56 83 a5 f8 f7 ff ff 00 8d b5 f8 f7 ff ff e8 ?? ?? ?? ?? 8a 85 f8 f7 ff ff 30 04 3b 83 7d 08 0f 75}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GCleaner_UFF_2147919912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GCleaner.UFF!MTB"
        threat_id = "2147919912"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GCleaner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {56 83 a5 f8 f7 ff ff 00 8d b5 f8 f7 ff ff e8 ?? ?? ?? ?? 8b 85 f4 f7 ff ff 8a 8d f8 f7 ff ff 30 0c 38 83 fb 0f 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GCleaner_KGF_2147920084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GCleaner.KGF!MTB"
        threat_id = "2147920084"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GCleaner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 d0 8b 44 24 1c c1 e8 05 89 44 24 18 8b 44 24 18 03 44 24 3c 33 ca 33 c1 81 3d ?? ?? ?? ?? 13 02 00 00 c7 05 ?? ?? ?? ?? ee 3d ea f4 89 44 24 18 0f 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GCleaner_KAA_2147920162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GCleaner.KAA!MTB"
        threat_id = "2147920162"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GCleaner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 8d f8 f7 ff ff 8b 85 f4 f7 ff ff 30 0c 38 83 fb 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GCleaner_AMAJ_2147920203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GCleaner.AMAJ!MTB"
        threat_id = "2147920203"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GCleaner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 85 d8 f7 ff ff 30 14 38 83 fb 0f 75 ?? 8d 85 ?? ?? ff ff 50 8d 8d ?? ?? ff ff 51 ff 15 ?? ?? ?? ?? 47 3b fb 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GCleaner_KGQ_2147920233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GCleaner.KGQ!MTB"
        threat_id = "2147920233"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GCleaner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 d0 8b 44 24 18 c1 e8 05 89 44 24 14 8b 44 24 14 03 44 24 34 33 ca 33 c1 81 3d ?? ?? ?? ?? 13 02 00 00 c7 05 ?? ?? ?? ?? ee 3d ea f4 89 44 24 14 0f 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

