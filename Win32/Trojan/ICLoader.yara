rule Trojan_Win32_ICLoader_DSK_2147742671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.DSK!MTB"
        threat_id = "2147742671"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 4d 0c 03 4d 08 8b 15 ?? ?? ?? ?? 8a 04 11 32 05 ?? ?? ?? ?? 8b 4d 0c 03 4d 08 8b 15 ?? ?? ?? ?? 88 04 11 8b 45 08 83 c0 01 89 45 08 81 7d 08 44 07 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_PDSK_2147744125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.PDSK!MTB"
        threat_id = "2147744125"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 54 24 0c 53 8a 1c 01 32 da 88 1c 01 8b 44 24 0c 83 f8 10 5b 75}  //weight: 2, accuracy: High
        $x_2_2 = {8a 1c 06 8a 14 0a 41 32 da 88 1c 06 8b c1 83 e8 10 5e f7 d8 1b c0 5b 23 c1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_ICLoader_VDSK_2147744557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.VDSK!MTB"
        threat_id = "2147744557"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 55 0c 03 c1 8a 0d ?? ?? ?? ?? 03 c2 8a 10 32 d1 8b 4d 08 88 10 83 3d ?? ?? ?? ?? 03 76}  //weight: 2, accuracy: Low
        $x_2_2 = {8a 0c 11 88 0c 06 8a 8a ?? ?? ?? ?? 84 c9 75 ?? 8b 0d ?? ?? ?? ?? 03 ca 03 c1 8a 0d ?? ?? ?? ?? 30 08 83 3d ?? ?? ?? ?? 03 7e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_ICLoader_PVD_2147751663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.PVD!MTB"
        threat_id = "2147751663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 7c 24 10 8b f5 c1 ee 05 03 74 24 34 81 3d ?? ?? ?? ?? b4 11 00 00 75 0a 00 c7 05}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 45 08 8d 34 07 e8 ?? ?? ?? ?? 30 06 83 65 fc 00 c1 eb 09}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_ICLoader_PVS_2147754537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.PVS!MTB"
        threat_id = "2147754537"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 7d 0c 03 7d 08 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 f8 66 33 c0 8a 65 ff 80 c9 ?? 0c ?? 30 27 61 ff 45 08 e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_JL_2147838024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.JL!MTB"
        threat_id = "2147838024"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {8b 55 fc 8a 04 1a 32 04 0e 32 c1 42 83 fa 0f 89 55 fc 76 09 81 e2 00 01 00 00 89 55 fc 88 04 0e 41 3b cf 72 db}  //weight: 6, accuracy: High
        $x_1_2 = "NetworkMiner" ascii //weight: 1
        $x_1_3 = "Wireshark" ascii //weight: 1
        $x_1_4 = "roxifier" ascii //weight: 1
        $x_1_5 = "HTTP Analyzer" ascii //weight: 1
        $x_1_6 = "/c taskkill /im" ascii //weight: 1
        $x_1_7 = "/f & erase" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_6_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ICLoader_JLK_2147838685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.JLK!MTB"
        threat_id = "2147838685"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {c1 e9 04 c1 e2 04 0b ca eb 05 33 c9 8a 0c 18 8b 55 f4 8b 75 08 88 0c 32 42 89 55 f4 40 8b 75 ec 8a 55 ff 46 d0 e2 83 fe 08 89 75 ec 88 55 ff 0f 8c 9b fd ff ff eb 6e 8a 4d f8 84 c9 74 14 8a 4c 18 fc c6 45 f8 00 81 e1 fc 00 00 00 c1 e1 05 40 eb 0d}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_RD_2147851719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.RD!MTB"
        threat_id = "2147851719"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 57 8b 3d 78 01 65 00 68 7c 32 65 00 ff d7 8b 35 74 01 65 00 a3 70 41 a5 00 85 c0 0f 84 ff 00 00 00 68 64 32 65 00 50 ff d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_RD_2147851719_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.RD!MTB"
        threat_id = "2147851719"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {d0 16 66 00 83 c4 04 03 ?? 89 ?? d0 16 66 00 e8 ?? ?? 00 00 e9}  //weight: 5, accuracy: Low
        $x_1_2 = "burningstudio.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_RD_2147851719_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.RD!MTB"
        threat_id = "2147851719"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c0 5e 5b 5d c3 8b c6 5e 5b 5d c3 90 90 90 90 90 90 90 90 90 90 90 90 90 55 8b ec 57 e9}  //weight: 1, accuracy: High
        $x_1_2 = "CortexLauncherService.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_RE_2147851734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.RE!MTB"
        threat_id = "2147851734"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5d c3 8b c6 5e 5b 5d c3 90 90 90 90 90 90 90 90 90 90 90 90 90 55 8b ec 57 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_RH_2147852570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.RH!MTB"
        threat_id = "2147852570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c0 5e 5b 5d c3 8b c6 5e 5b 5d c3 90 90 90 90 90 90 90 90 90 90 90 90 90 55 8b ec 51 53 56 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_GMC_2147853180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.GMC!MTB"
        threat_id = "2147853180"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {a1 04 28 46 01 89 35 1c 13 46 01 8b fe 38 18 74 ?? 8b f8 8d 45 f8 50 8d 45 fc}  //weight: 10, accuracy: Low
        $x_1_2 = "@.dcs811" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_EM_2147888905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.EM!MTB"
        threat_id = "2147888905"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "_rstefgh_6_11221_" ascii //weight: 5
        $x_5_2 = "_qrsabcd_3_11201_" ascii //weight: 5
        $x_5_3 = "_qrsabcd_2_11202_" ascii //weight: 5
        $x_1_4 = "AlphaBlend" ascii //weight: 1
        $x_1_5 = "CsrNewThread" ascii //weight: 1
        $x_1_6 = "NtAccessCheckByTypeResultListAndAuditAlarm" ascii //weight: 1
        $x_1_7 = "CsrClientCallServer" ascii //weight: 1
        $x_1_8 = "DbgPrompt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ICLoader_RPX_2147897491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.RPX!MTB"
        threat_id = "2147897491"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 33 ff 57 ff d6 83 f8 07 75 1f 6a 01 ff d6 25 00 ff 00 00 3d 00 0d 00 00 74 07 3d 00 04 00 00 75 08 5f b8 01 00 00 00 5e c3 8b c7 5f 5e c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_RPX_2147897491_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.RPX!MTB"
        threat_id = "2147897491"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {62 c3 5a 00 ff 21 57 00 00 da 0a 00 73 5b 0d ca ac c1 56 00 00 d4 00 00 29 42 b3 73}  //weight: 1, accuracy: High
        $x_1_2 = "MIXAudio" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_RPX_2147897491_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.RPX!MTB"
        threat_id = "2147897491"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 87 33 00 25 e6 2f 00 00 da 0a 00 73 5b 0d ca 92 aa 2f 00 00 d4 00 00 55 63 05 9b}  //weight: 1, accuracy: High
        $x_1_2 = "Qt5OpenGL" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_RPX_2147897491_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.RPX!MTB"
        threat_id = "2147897491"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {9d 7a 74 00 14 df 70 00 00 be 0a 00 0b 33 49 b9 c7 97 70 00 00 dc 01 00 1f d0 c2 43}  //weight: 1, accuracy: High
        $x_1_2 = "QTRadioButton" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_RPX_2147897491_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.RPX!MTB"
        threat_id = "2147897491"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {d7 7b 0b 2a 01 00 00 00 99 60 49 00 b5 cb 45 00 00 ae 0a 00 23 97 28 5f 6c 90 45 00 00 d4 00 00 d8 96 a9 71}  //weight: 10, accuracy: High
        $x_10_2 = {7b 4b 49 00 97 b6 45 00 00 ae 0a 00 23 97 28 5f 3b 7b 45 00 00 d4 00 00 4d c2 0b 88}  //weight: 10, accuracy: High
        $x_1_3 = "BusinessTV" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ICLoader_RPY_2147897492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.RPY!MTB"
        threat_id = "2147897492"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 30 8b 04 24 50 89 e0 05 04 00 00 00 51 b9 04 00 00 00 01 c8 59 33 04 24 31 04 24 33 04 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_RPY_2147897492_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.RPY!MTB"
        threat_id = "2147897492"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 96 84 00 85 f5 80 00 00 da 0a 00 73 5b 0d ca 36 b8 80 00 00 d4 00 00 f8 3c 15 20}  //weight: 1, accuracy: High
        $x_1_2 = "XRECODE 3" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_RPY_2147897492_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.RPY!MTB"
        threat_id = "2147897492"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5d 55 6c 00 fa b3 68 00 00 da 0a 00 73 5b 0d ca 37 3e 68 00 00 d4 00 00 4d 7d f5 28}  //weight: 1, accuracy: High
        $x_1_2 = "AudioSwitch" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_RPY_2147897492_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.RPY!MTB"
        threat_id = "2147897492"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {14 64 74 00 8b c8 70 00 00 be 0a 00 0b 33 49 b9 78 81 70 00 00 dc 01 00 6a 8d 5e 14}  //weight: 10, accuracy: High
        $x_10_2 = {ba 73 74 00 31 d8 70 00 00 be 0a 00 0b 33 49 b9 10 91 70 00 00 dc 01 00 80 f1 86 03}  //weight: 10, accuracy: High
        $x_1_3 = "DTPanelQT" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ICLoader_RPZ_2147898774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.RPZ!MTB"
        threat_id = "2147898774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {86 5b fd cc 5a f5 d6 42 08 41 84 27 a3 72 f7 20 92}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_RPZ_2147898774_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.RPZ!MTB"
        threat_id = "2147898774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c6 04 57 8d 4d f8 56 8b 75 08 51 50 89 45 e0 ff 56 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_TUAA_2147918346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.TUAA!MTB"
        threat_id = "2147918346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? b2 65 00 68 ?? 5e 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 65 00 33 d2 8a d4 89 15 ?? 27 a6 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 27 a6 00 c1 e1 08 03 ca 89 0d ?? 27 a6 00 c1 e8 10 a3 ?? 27 a6 00 33 f6 56 e8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_MBXQ_2147918807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.MBXQ!MTB"
        threat_id = "2147918807"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 ?? 08 4c 00 68 ?? a7 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? 02 4c 00 33 d2 8a d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_VGAA_2147920113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.VGAA!MTB"
        threat_id = "2147920113"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? c6 65 00 68 ?? 65 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 65 00 33 d2 8a d4 89 15 ?? 4d a6 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 4d a6 00 c1 e1 08 03 ca 89 0d ?? 4d a6 00 c1 e8 10 a3 ?? 4d a6 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_BAK_2147927735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.BAK!MTB"
        threat_id = "2147927735"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {c1 e2 04 a1 ?? ?? ?? 00 23 c2 a3 ?? ?? ?? 00 33 c9 8a 0d ?? ?? ?? 00 8b 15 ?? ?? ?? 00 83 e2 08 0f af ca a1 ?? ?? ?? 00 0b c1 a3}  //weight: 3, accuracy: Low
        $x_2_2 = {89 45 fc 8a 0d ?? ?? ?? 00 32 0d ?? ?? ?? 00 88 0d ?? ?? ?? 00 33 d2 8a 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_MBWD_2147927800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.MBWD!MTB"
        threat_id = "2147927800"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 ?? 99 4f 00 68 ?? 3c 4c 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? 71 4c 00 33 d2 8a d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_BK_2147927958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.BK!MTB"
        threat_id = "2147927958"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {83 ec 14 a0 ?? ?? ?? 00 8a 0d ?? ?? ?? 00 32 c8 8d 54 24 04 88 0d ?? ?? ?? 00 8a 0d ?? ?? ?? 00 80 c9 0c 52 c0 e9 02 81 e1 ff 00 00 00 89 4c 24 04 db 44 24 04}  //weight: 4, accuracy: Low
        $x_1_2 = {55 8b ec 83 ec 0c 53 56 57 b9 ?? ?? 66 00 e8 ?? ?? fb ff 89 45 fc e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_MBWE_2147928037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.MBWE!MTB"
        threat_id = "2147928037"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 ?? 18 4c 00 68 ?? b7 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? 12 4c 00 33 d2 8a d4 89 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_AIC_2147928054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.AIC!MTB"
        threat_id = "2147928054"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b f8 a1 34 30 4c 00 c7 44 24 10 00 00 00 00 8d 14 09 8b 1d 20 11 4c 00 0b d0 68 9c 30 4c 00 89 54 24 10 57 df 6c 24 14 dc 05 58 30 4c 00 dd 1d 58 30 4c 00 ff d3 89 06 68 88 30 4c 00 57 ff d3 89 46 04 68 74 30 4c 00 57 ff d3 89 46 08 68 64 30 4c 00 57 ff d3 8b 0e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_GNM_2147928072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.GNM!MTB"
        threat_id = "2147928072"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 44 24 10 33 c8 8b c1 33 cf 5f 81 f9 ?? ?? ?? ?? 5e 75 ?? b9 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? f7 d1 89 0d ?? ?? ?? ?? 83 c4 ?? c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_BAL_2147928239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.BAL!MTB"
        threat_id = "2147928239"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8d 0c 00 0b ca 89 4c 24 04 df 6c 24 04 dc 05 ?? ?? 4d 00 dd 1d ?? ?? 4d 00 ff 15 ?? ?? 4c 00 a3 ?? ?? 4d 00 83 c4 08 c3}  //weight: 4, accuracy: Low
        $x_1_2 = {55 8b ec 83 ec 10 53 56 57 e8 ?? ?? f5 ff 89 45 fc e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_MBWH_2147928624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.MBWH!MTB"
        threat_id = "2147928624"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 ?? e7 65 00 68 ?? 87 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? e3 65 00 33 d2 8a d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_MBWH_2147928624_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.MBWH!MTB"
        threat_id = "2147928624"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 ?? fa 65 00 68 ?? 8c 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? f4 65 00 33 d2 8a d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_AFHA_2147928966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.AFHA!MTB"
        threat_id = "2147928966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? c6 4c 00 68 ?? 62 4c 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 4c 00 33 d2 8a d4 89 15 ?? 4e 4d 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 4e 4d 00 c1 e1 08 03 ca 89 0d ?? ?? 4d 00 c1 e8 10 a3 ?? 4d 4d 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_AIHA_2147929021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.AIHA!MTB"
        threat_id = "2147929021"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? c7 4c 00 68 ?? 64 4c 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 4c 00 33 d2 8a d4 89 15 ?? 5d 4d 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 5d 4d 00 c1 e1 08 03 ca 89 0d ?? 5d 4d 00 c1 e8 10 a3 ?? 5d 4d 00 6a 01}  //weight: 5, accuracy: Low
        $x_5_2 = {55 8b ec 6a ff 68 ?? b7 4c 00 68 ?? 54 4c 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 4c 00 33 d2 8a d4 89 15 ?? 4d 4d 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 4d 4d 00 c1 e1 08 03 ca 89 0d ?? 4d 4d 00 c1 e8 10 a3 ?? 4d 4d 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

