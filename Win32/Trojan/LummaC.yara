rule Trojan_Win32_LummaC_B_2147891669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.B!MTB"
        threat_id = "2147891669"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 3c 02 89 d9 80 e1 18 d3 e7 89 c1 83 e1 fc 31 7c 0c 14 40 83 c3 08 39 c6 75 e4}  //weight: 1, accuracy: High
        $x_1_2 = "cmd.exe /c timeout /nobreak /t 3 & fsutil file setZeroData offset=0 length=%lu \"%s\" & erase \"%s\" & exit" ascii //weight: 1
        $x_1_3 = "gstatic-node.io" ascii //weight: 1
        $x_1_4 = "TeslaBrowser" ascii //weight: 1
        $x_1_5 = "*.eml" ascii //weight: 1
        $x_1_6 = "powershell -exec bypass \"%s\"" ascii //weight: 1
        $x_1_7 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_A_2147893962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.A!MTB"
        threat_id = "2147893962"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 4c 24 04 b8 d1 05 00 00 01 44 24 04 8b 54 24 04 8a 04 32 8b 0d ?? ?? ?? ?? 88 04 31 81 c4 1c 08 00 00 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4c 24 10 8b c6 c1 e8 05 03 44 24 20 03 cd 33 c1 8d 0c 33 33 c1 2b f8 8b d7 c1 e2 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_GAA_2147906160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.GAA!MTB"
        threat_id = "2147906160"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 44 24 10 30 0c 06 83 ff ?? ?? ?? 6a 00 6a 00 6a 00 ff d3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_GMK_2147907896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.GMK!MTB"
        threat_id = "2147907896"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {f6 17 80 07 ?? b8 ?? ?? ?? ?? b8 ?? ?? ?? ?? 80 2f ?? f6 2f 47 e2}  //weight: 10, accuracy: Low
        $x_10_2 = {f6 17 80 07 ?? b8 ?? ?? ?? ?? bb ?? ?? ?? ?? b8 ?? ?? ?? ?? 80 2f ?? f6 2f 47 e2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_LummaC_ASGE_2147908308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.ASGE!MTB"
        threat_id = "2147908308"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 c2 8b 55 f4 33 d0 89 55 f4 e8}  //weight: 2, accuracy: High
        $x_2_2 = {81 01 e1 34 ef c6 c3 29 11 c3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_ASGF_2147908632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.ASGF!MTB"
        threat_id = "2147908632"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0f b6 44 2c ?? 03 c6 0f b6 c0 8a 44 04 ?? 30 04 39 8b 4c 24 ?? 85 c9 74}  //weight: 4, accuracy: Low
        $x_1_2 = "divuhxIUo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_ASGH_2147910142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.ASGH!MTB"
        threat_id = "2147910142"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0f b6 44 3c ?? 03 c6 59 59 8b 4c 24 ?? 0f b6 c0 8a 44 04 ?? 30 04 29 45 3b ac 24}  //weight: 4, accuracy: Low
        $x_1_2 = "daixiAis" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_AMAE_2147910594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.AMAE!MTB"
        threat_id = "2147910594"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 14 30 83 ff 0f 75 ?? 8b 8d ?? ?? ?? ?? 6a 00 6a 00 [0-15] 50 51 68}  //weight: 1, accuracy: Low
        $x_1_2 = {30 0c 33 83 ff 0f 75 ?? 8b 95 [0-15] 6a 00 6a 00 [0-15] 50 51 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_LummaC_KAA_2147910698_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.KAA!MTB"
        threat_id = "2147910698"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 75 88 8a 84 05 ?? ?? ?? ?? 30 04 0b 43 3b 9d ?? ?? ?? ?? 89 5d ?? 8b 5d ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_ASGI_2147910711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.ASGI!MTB"
        threat_id = "2147910711"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 d0 0f b6 10 0f b6 45 ?? 0f b6 84 05 ?? ?? ?? ?? 31 d0 88 45 ?? 8b 55 f0 8b 45 0c 01 c2 0f b6 45 ?? 88 02 83 45 f0 01 8b 45 f0 3b 45 10 0f 8c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_ASGJ_2147910942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.ASGJ!MTB"
        threat_id = "2147910942"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff 8b 44 24 ?? 8d 4c 24 ?? 8a 44 04 ?? 30 07 e8 ?? ?? ?? 00 8b 5c 24 ?? 47 8b 54 24 ?? 6a 0f 5d 81 ff}  //weight: 2, accuracy: Low
        $x_2_2 = {0f b6 44 1c ?? 03 c6 33 ed 0f b6 c0 59 89 44 24}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_AMAA_2147912540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.AMAA!MTB"
        threat_id = "2147912540"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 6d fc 46 8b 45 08 8a 4d fc 03 c2 30 08 42 3b d7 7c ?? 5e 83 ff 2d 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_GXL_2147913228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.GXL!MTB"
        threat_id = "2147913228"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 45 c4 50 e8 ?? ?? ?? ?? 8a 45 c4 30 04 37 59 83 fb 0f}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_ASGK_2147913926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.ASGK!MTB"
        threat_id = "2147913926"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {c1 e3 04 03 9d ?? ?? ff ff 33 d9 81 3d ?? ?? ?? 00 03 0b 00 00 75 13 6a 00 ff 15 ?? ?? ?? 00 33 c0 50 50 50 ff 15 ?? ?? ?? 00 8b 45 6c 33 c3 2b f0}  //weight: 4, accuracy: Low
        $x_1_2 = {2b f8 83 3d ?? ?? ?? 00 0c 89 45 6c 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_MZT_2147913948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.MZT!MTB"
        threat_id = "2147913948"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 44 34 ?? 03 c2 0f b6 c0 0f b6 44 04 ?? 30 83 ?? ?? ?? ?? 43 81 fb ?? ?? ?? ?? 7c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_GNU_2147914108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.GNU!MTB"
        threat_id = "2147914108"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {03 55 e0 0f b6 02 33 45 dc 8b 4d 14 03 4d e0 88 01 8d 4d e4}  //weight: 10, accuracy: High
        $x_1_2 = "IUAhsiuchniuohAIU" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_MAT_2147914796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.MAT!MTB"
        threat_id = "2147914796"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 74 24 30 8b 0c 87 0f b6 04 06 6a 03 30 81}  //weight: 1, accuracy: High
        $x_1_2 = {45 89 6c 24 14 81 fd ?? ?? ?? ?? 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_MAB_2147914927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.MAB!MTB"
        threat_id = "2147914927"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7c 24 30 8b 0c b3 0f b6 04 37 6a 03 30 81 ?? ?? ?? ?? b9}  //weight: 1, accuracy: Low
        $x_1_2 = {45 89 6c 24 14 81 fd ?? ?? ?? ?? 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_AMAJ_2147915158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.AMAJ!MTB"
        threat_id = "2147915158"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d8 8b 45 ?? 31 18 6a 00 e8 [0-20] 83 45 ec 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_RDB_2147915331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.RDB!MTB"
        threat_id = "2147915331"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 6c 24 28 8b 5c 24 34 8b 54 24 40 59 8b 4c b5 00 8a 04 33 6a 03 30 04 11 b9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_MAC_2147915505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.MAC!MTB"
        threat_id = "2147915505"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 03 8b 4c 85 ?? 8a 04 18 30 04 11 b9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_ASGV_2147916172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.ASGV!MTB"
        threat_id = "2147916172"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8a 04 01 8b 4c 24 ?? 30 04 0a 8d 4c}  //weight: 4, accuracy: Low
        $x_1_2 = "JAHNsiu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_CCJF_2147917324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.CCJF!MTB"
        threat_id = "2147917324"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {21 d0 01 f0 89 c2 31 ca f7 d0 21 c8 01 c0 29 d0}  //weight: 5, accuracy: High
        $x_5_2 = {21 ca 01 c8 01 d2 29 d0 05 ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 04 ?? 8b 0c 24 88 44 0c 08 ff 04 24 8b 04 24 83 f8}  //weight: 5, accuracy: Low
        $x_5_3 = {21 d0 01 c0 89 ca f7 d2 21 c2 f7 d0 21 c8 29 d0 89 44 24}  //weight: 5, accuracy: High
        $x_5_4 = {21 c8 09 ca 29 c2 89 54 24 ?? 8b 44 24 ?? 04 1d 8b 0c 24 88 44 0c ?? ff 04 24 8b 04 24 83 f8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_LummaC_CZ_2147917460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.CZ!MTB"
        threat_id = "2147917460"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0c 98 8b 44 24 ?? 8a 04 01 8d 4c 24 ?? 30 82}  //weight: 1, accuracy: Low
        $x_1_2 = {46 89 74 24 ?? 81 fe ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_ASGW_2147917802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.ASGW!MTB"
        threat_id = "2147917802"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 04 01 8d 4c 24 ?? 30 82 [0-4] e8 ?? ?? ?? ?? 8d 4c 24 ?? e8 ?? ?? ?? ?? 8d 4c 24 ?? e8 ?? ?? ?? ?? 8d 4c 24 ?? e8 ?? ?? ?? ?? 46 89 74 24 ?? 81 fe ?? ?? ?? 00 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_ALC_2147917813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.ALC!MTB"
        threat_id = "2147917813"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 d7 81 e7 00 b7 67 da 89 d3 81 f3 00 b7 67 5a 21 f2 8d 3c 7b 01 f7 01 d2 29 d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_CCJK_2147919210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.CCJK!MTB"
        threat_id = "2147919210"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {d4 45 d0 4b c7 44 24 ?? ee 49 e4 4f c7 44 24 ?? e2 4d 9e 33 c7 44 24 ?? 96 31 9c 37 c7 44 24 ?? 9a 35 34 3b}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_ASN_2147919709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.ASN!MTB"
        threat_id = "2147919709"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {f6 17 90 89 d8 bb 99 00 00 00 90 31 c3 80 07 79 80 2f 35 90 89 d8 bb 99 00 00 00 90 31 c3 f6 2f 47 e2}  //weight: 4, accuracy: High
        $x_4_2 = {8b 0a 8b 3e f6 17 53 5b 90 89 c3 83 f3 39 80 07 47 80 2f 25 53 5b 90 89 c3 83 f3 39 f6 2f 47 e2}  //weight: 4, accuracy: High
        $x_1_3 = {20 ca 30 c8 08 c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_LummaC_CCJP_2147920161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.CCJP!MTB"
        threat_id = "2147920161"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 ec 8b 4d ec 0f b6 0c 0f 05 ?? ?? ?? ?? 31 c8 89 45 e8 8b 45 e8 04 6e 8b 4d ec 88 04 0f ff 45 ec 8b 45 ec 83 f8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_AMAH_2147920215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.AMAH!MTB"
        threat_id = "2147920215"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 00 8b 4d ?? 83 c1 ?? 0f be c9 33 c1 8b 4d [0-4] 03 4d ?? 88 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_CCJG_2147920706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.CCJG!MTB"
        threat_id = "2147920706"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 08 03 45 fc 0f b6 08 8b 15 ?? ?? ?? ?? 81 c2 96 00 00 00 33 ca 8b 45 08 03 45 fc 88 08 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_CCJL_2147920707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.CCJL!MTB"
        threat_id = "2147920707"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 0c 1a 8d 43 ?? 30 01 43 83 fb 14 72 f2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_CCJM_2147920708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.CCJM!MTB"
        threat_id = "2147920708"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {89 ce 21 d6 01 f6 29 f2 01 ca 89 54 24}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_CCJN_2147920709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.CCJN!MTB"
        threat_id = "2147920709"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {29 cf 81 c1 ?? ?? ?? ?? 31 cf 21 d7 31 cf 89 7e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_CCJO_2147920710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.CCJO!MTB"
        threat_id = "2147920710"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 0c 24 8b 14 24 0f b6 54 14 ?? 81 c1 ?? ?? ?? ?? 31 d1 89 8c 24 ?? ?? ?? ?? 8b 8c 24 ?? ?? ?? ?? 80 c1 ?? 8b 14 24 88 4c 14 ?? ff 04 24 8b 0c 24 83 f9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_CCJQ_2147920712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.CCJQ!MTB"
        threat_id = "2147920712"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f6 17 58 50 89 c0 35 ?? ?? ?? ?? 90 80 07 64 80 2f 88 58 50 89 c0 35 ?? ?? ?? ?? 90 f6 2f 47 e2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

