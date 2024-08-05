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
        $x_5_1 = {8a 04 01 8d 4c 24 ?? 30 82 [0-4] e8 ?? ?? ?? ff 8d 4c 24 ?? e8 ?? ?? ?? ff 8d 4c 24 ?? e8 ?? ?? ?? ff 8d 4c 24 ?? e8 ?? ?? ?? ff 46 89 74 24 ?? 81 fe ?? ?? ?? 00 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

