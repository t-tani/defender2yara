rule TrojanDownloader_Win32_Rugmi_B_2147898934_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.B!MTB"
        threat_id = "2147898934"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 0c 16 83 c2 ?? 39 c2}  //weight: 2, accuracy: Low
        $x_2_2 = {31 3c 03 83 c0 ?? 39 f0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_SB_2147899734_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.SB!MTB"
        threat_id = "2147899734"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 44 0d 08 30 04 32 8d 41 ?? 83 e9 ?? 42 f7 d9 1b c9 23 c8 3b d7 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_SA_2147902124_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.SA!MTB"
        threat_id = "2147902124"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c1 83 c1 ?? 89 4c 24 ?? 83 f8 ?? 74 ?? 8b 44 24 ?? 8a ?? 8b 0c 24 88 01 8b 04 24 83 c0 ?? 89 04 24 8b 44 24 ?? 83 c0 ?? 89 44 24 ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = "\\NewToolsProject\\SQLite3Encrypt\\Release\\SQLite3Encrypt.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_C_2147902177_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.C!MTB"
        threat_id = "2147902177"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 c0 03 45 ?? 89 45 a4 8b 45 a4 8b ?? 33 85 58 ?? ?? ?? 8b 4d a4 89 01 8b 45 d4 83 c0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_HNS_2147906499_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.HNS!MTB"
        threat_id = "2147906499"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 42 3c 0f be 0b 8b 7c 10 2c 8d 44 24 10 8b 6c 0b 04 8d 71 0c 50 6a 40 03 f3 03 fa 8b 5c 0b 08 53 57 c7 44 24 20 00 00 00 00}  //weight: 10, accuracy: High
        $x_10_2 = {53 ff 54 24 2c 8b 0d ?? ?? ?? ?? 8b 44 24 04 8d ?? 08 8b ?? 04 8d ?? 08 89 ?? 24 8d ?? 08 f7 d8 03 ?? 3d f8 ?? 00 00 7d 0d f7 d8 3d f8 ?? 00 00}  //weight: 10, accuracy: Low
        $x_10_3 = {89 45 ec 8b 45 fc 8b 40 5c 89 45 f0 83 65 e8 00 8b 45 f0 83 38 00 74 3f ff 75 ec}  //weight: 10, accuracy: High
        $x_10_4 = {00 83 ec 10 03 43 0c 01 d8 01 d3 89 1c 24 ff d0 c7 04 24 00 00 00 00 ff}  //weight: 10, accuracy: High
        $x_10_5 = {6a 04 58 6b c0 00 8b 4d f0 8b 55 e8 3b 14 01 74 ?? 6a 04 58 c1 e0 00 8b 4d f0 8b 55 e8 3b 14 01 74 08 6a 00}  //weight: 10, accuracy: Low
        $x_10_6 = {89 c1 41 8b 44 0e 04 4c 01 f1 48 83 c1 08 ba 04 00 00 00 8b 74 11 fc 01 c6 89 74 17 04 48 83 c2 04 48 81 fa ?? ?? 00 00 72 ?? 8b 05 ?? ?? ?? ?? 89 47 08}  //weight: 10, accuracy: Low
        $x_5_7 = {8b 4f 0c 03 c8 a1 ?? ?? ?? ?? 03 cf 03 f8 57 ff d1 83 c4 04 6a 00 ff}  //weight: 5, accuracy: Low
        $x_5_8 = {8b 5e 04 2b f7 8b 04 0e 8d 49 04 03 c3 89 41 fc 83 ea 01 75 f0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Rugmi_HNA_2147907068_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.HNA!MTB"
        threat_id = "2147907068"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c0 0f 95 c0 84 c0 74 15 8b 45 ?? 0f b6 00 8b 55 ?? 88 02 83 45 ?? 01 83 45 ?? 01 eb d9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_HNC_2147907261_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.HNC!MTB"
        threat_id = "2147907261"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 74 11 fc 01 c6 89 74 13 04 83 c2 04 81 fa fc 5f 00 00 72 eb}  //weight: 1, accuracy: High
        $x_1_2 = {03 43 0c 01 d8 01 d3 89 1c 24 ff d0 c7 04 24 00 00 00 00 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {8b 44 24 1c 33 d2 66 89 14 48 89 44 24 24 8d 04 33 89 44 24 20 8d 44 24 20 50 c6 44 24 2c 01 ff d7}  //weight: 1, accuracy: High
        $x_1_4 = {8b 55 fc 0f be 02 03 45 fc 89 45 fc 8b 4d fc 83 c1 01 51 ff 55 b0 89 45}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_HND_2147907821_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.HND!MTB"
        threat_id = "2147907821"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 03 8b 00 8b 55 08 03 42 e4 83 c0 02 8b 55 08 89 42 cc 8b 45 08 8b 40 cc 50 8b 07 50 ff}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 fc 83 c0 02 8d 14 85 00 00 00 00 8b 45 f8 01 d0 8b 08 8b 45 fc 8d 14 85 00 00 00 00 8b 45 0c 01 d0 8b 55 f0 01 ca 89 10 83 45 fc 01 eb c8}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 08 8d 55 e0 c7 44 24 0c 08 00 00 00 8b 4d 0c 89 54 24 08 29 d8 43}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_HNF_2147909118_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.HNF!MTB"
        threat_id = "2147909118"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 ca 89 10 83 45 ?? 01 30 00 [0-48] 8b 45 ?? 39 45 ?? 76 [0-8] 8b 45 [0-8] 8b 08 [0-16] 01 ca [0-16] 83 45 ?? 01 [0-16] 83 c0 04 [0-8] 89 45 [0-8] eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_HNE_2147909713_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.HNE!MTB"
        threat_id = "2147909713"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c0 0f 95 c0 84 c0 74 ?? 8b 45 0c 0f b6 00 8b 55 30 00 [0-37] 55 89 e5 83 ec [0-32] 8d 50 ff [0-32] 88 02 [0-32] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_HNI_2147910066_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.HNI!MTB"
        threat_id = "2147910066"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 10 89 45 fc b8 ff ff ff ?? 03 45 10 89 45 10 8b 45 fc 85 c0 74 23 8b 45 0c 8b 55 08 0f be 00 88 02 b8 01 00 00 00 03 45 08 89 45 08 b8 01 00 00 00 03 45 0c 89 45 0c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_SG_2147912598_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.SG!MTB"
        threat_id = "2147912598"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hidden" wide //weight: 1
        $x_1_2 = "WixBurn" wide //weight: 1
        $x_1_3 = "aphagia.exe" wide //weight: 1
        $x_1_4 = "//appsyndication.org" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_EC_2147912710_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.EC!MTB"
        threat_id = "2147912710"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {eb 0c 8b 4d f8 8b 51 18 03 55 f4 89 55 f4 8b 45 f8 8b 48 10 39 4d f4 73 15 8b 55 e8 03 55 f4 8b 02 03 45 dc 8b 4d f0 03 4d f4 89 01 eb d4}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_HNN_2147912837_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.HNN!MTB"
        threat_id = "2147912837"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 04 08 83 f8 00 74 ?? 8b 45 ?? 8b 4d ?? 0f be 04 08 8b 4d ?? 8b 55 ?? 66 89 04 51 8b 45 ?? 83 c0 01 89 45 ?? 8b 45 ?? 83 c0 01 89 45 ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {24 c7 44 24 ?? 01 00 00 00 c7 44 24 ?? 01 00 00 00 c7 44 24 ?? 00 00 00 00 c7 44 24 ?? 03 00 00 00 c7 44 24 ?? 80 00 00 00 c7 44 24 ?? 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {03 01 89 01 8b 45 ?? 83 c0 01 89 45}  //weight: 1, accuracy: Low
        $x_1_4 = {66 c7 04 48 00 00 8b 45 ?? 89 85 ?? ?? ?? ?? 8b 45 ?? 89 85 ?? ?? ?? ?? c6 85 ?? ?? ?? ?? 01 8b 45 ?? 89 45 ?? 8d 85 ?? ?? ?? ?? 89 04 24 ff 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_EM_2147915506_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.EM!MTB"
        threat_id = "2147915506"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 45 c4 83 65 e0 00 83 65 dc 00 83 65 d8 00 6a 00 6a 00 6a 00 6a 01 8b 45 fc ff 70 48}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_HNR_2147917803_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.HNR!MTB"
        threat_id = "2147917803"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 51 51 83 65 fc 00 83 65 f8 00 33 c0 40 74 2e 8b 45 fc 8b 4d 08 0f b7 04 41 83 f8 5c 75 06 8b 45 fc 89 45 f8 8b 45 fc 8b 4d 08 0f b7 04 41 85 c0 75 02 eb 09 8b 45 fc 40 89 45 fc eb cd 8b 45 f8 8b 4d 08 8d 44 41 02 8b e5 5d c3}  //weight: 5, accuracy: High
        $x_1_2 = {59 6a 00 ff 15 17 00 [0-16] 8b 00 03 45 ?? 89 45 ?? 8b 45 ?? 89 45 ?? ff 75 ?? ff 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_HNT_2147918333_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.HNT!MTB"
        threat_id = "2147918333"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 45 08 89 45 f8 8b 45 10 89 45 fc 8b 45 10 48 89 45 10 83 7d fc 00 74 1a 8b 45 08 8b 4d 0c 8a 09 88 08 8b 45 08 40 89 45 08 8b 45 0c 40 89 45 0c}  //weight: 5, accuracy: High
        $x_2_2 = {55 8b ec 51 51 8b 45 08 89 45 fc 8b 45 0c 89 45 f8 8b 45 0c 48 89 45 0c 83 7d f8 00 76 0f 8b 45 fc c6 00 00 8b 45 fc 40 89 45 fc eb de 8b 45 08 8b e5 5d c3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_HNU_2147918597_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.HNU!MTB"
        threat_id = "2147918597"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 78 08 8d 04 3b 89 45 ?? 8b 46 3c 8b 44 06 2c 89}  //weight: 5, accuracy: Low
        $x_1_2 = {c7 04 24 00 00 00 00 89 44 24 04 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {89 04 24 ff d1 8d 65 ?? 59 5b 5e 5f 5d}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 44 24 0c 04 00 00 00 c7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_DA_2147921358_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.DA!MTB"
        threat_id = "2147921358"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af 74 24 0c 0f b6 0c 3a 03 f1 42 3b d0 72 ?? 5f 8b c6 5e c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

