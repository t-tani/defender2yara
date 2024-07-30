rule Trojan_Win32_Neoreblamy_AC_2147812835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.AC!MTB"
        threat_id = "2147812835"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 f4 0f b6 84 05 45 ff ff ff 8b 4d f4 2b 4d d0 0f b6 8c 0d 42 ff ff ff 0f be 8c 0d b8 fe ff ff 0b c1 8b 4d f4 0f b6 8c 0d 45 ff ff ff 8b 55 f4 2b 55 d0 0f b6 94 15 42 ff ff ff 0f be 94 15 b8 fe ff ff 23 ca 2b c1 8b 4d f4 0f b6 8c 0d 44 ff ff ff 88 84 0d b8 fe ff ff 83 65 d0 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_AC_2147812835_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.AC!MTB"
        threat_id = "2147812835"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b fe 8b 74 24 1c 8b cb d3 ff 8b c7 8d 4c 24 20 33 c6 99 52 50}  //weight: 2, accuracy: High
        $x_2_2 = {55 8b ec 83 e4 f8 83 ec 1c 53 c7 44 24 04 ?? ?? 00 00 81 7c 24 04 ?? ?? 00 00 56 57}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_AD_2147812836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.AD!MTB"
        threat_id = "2147812836"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {23 ca 2b c1 8b 4d ?? 0f b6 4c 0d ?? 8b 55 ?? 2b 55 ?? 0f b6 54 15 ?? 0f b7 54 55 ?? 23 ca 2b c1 8b 4d ?? 0f b6 4c 0d ?? 66 89 44 4d}  //weight: 10, accuracy: Low
        $x_3_2 = "FreeLibraryWhenCallbackReturns" ascii //weight: 3
        $x_3_3 = "GetLogicalProcessorInformation" ascii //weight: 3
        $x_3_4 = "SetThreadStackGuarantee" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_K_2147812837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.K!MTB"
        threat_id = "2147812837"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 40 c1 e0 00 0f b6 44 05 ?? 83 c8 ?? 33 c9 41 c1 e1 00 0f b6 4c 0d ?? 83 e1 ?? 2b c1 33 c9 41 6b c9 00 0f b6 4c 0d ?? 66 89 44 4d}  //weight: 1, accuracy: Low
        $x_1_2 = "I become the guy" ascii //weight: 1
        $x_1_3 = "Oh, my keyboard" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_KZ_2147812838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.KZ!MTB"
        threat_id = "2147812838"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OMG>.< I don't know!" ascii //weight: 1
        $x_1_2 = "ml. from cup #" ascii //weight: 1
        $x_1_3 = "fxotybyjkcgdtrtmootmfcwkogtivemkvoiulgkjkswecddhirekd" ascii //weight: 1
        $x_1_4 = "trhwhsllljbdrmkekvmqbcmutqhxgwwfrsaucbntctmqhlrybnrh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_KY_2147812839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.KY!MTB"
        threat_id = "2147812839"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "FORTRAN 77" ascii //weight: 1
        $x_1_2 = "ml. from cup #" ascii //weight: 1
        $x_1_3 = "FastestFinger" ascii //weight: 1
        $x_1_4 = "mgigqmstjshwnblvvvwyqmlgrmhlijadrwppnaeinmgonkgucnyogqyl" ascii //weight: 1
        $x_1_5 = {89 cb c1 e3 03 09 d3 00 dc be ?? ?? ?? ?? 66 ad 31 db 89 cb c1 e3 03 09 d3 00 dc be ?? ?? ?? ?? 66 ad 00 d4 b8 ff ff ff ff be ?? ?? ?? ?? 66 ad 00 d4 b8 ff ff ff ff be ?? ?? ?? ?? 66 ad 31 db 89 cb c1 e3 03 09 d3 00 dc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_CL_2147812840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.CL!MTB"
        threat_id = "2147812840"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 04 0a 33 c6 69 f0 93 01 00 01 42 83 fa 04 72 ee}  //weight: 1, accuracy: High
        $x_1_2 = {33 d2 8b c6 6a 0e 59 f7 f1 8b 45 08 8b 0c b3 8b 14 90 8b c1 23 c2 03 c0 2b c8 03 ca 89 0c b3 46 3b f7 72 dc}  //weight: 1, accuracy: High
        $x_1_3 = "GetTickCount" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_2147841147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy"
        threat_id = "2147841147"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wrutfk" ascii //weight: 1
        $x_1_2 = "nylqeso" ascii //weight: 1
        $x_1_3 = "lopnbd" ascii //weight: 1
        $x_1_4 = "gitgahc" ascii //weight: 1
        $x_2_5 = "ShowOwnedPopups" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Neoreblamy_EM_2147847197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.EM!MTB"
        threat_id = "2147847197"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {59 59 8b 4d f8 8b 09 03 c1 99 b9 07 ca 9a 3b f7 f9 8b 45 f8 89 10}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_EM_2147847197_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.EM!MTB"
        threat_id = "2147847197"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {89 45 fc 8b 45 fc 89 45 f8 8b 45 f8 8b 4d f8 8b 00 23 41 04 83 f8 ff 74 0a 8b 4d fc 8b 01 8b 51 04 eb 59 8b 45 fc 83 20 00 83 60 04 00 ff 75 0c 8b 45 0c 8b 4d 08}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_GJH_2147847355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.GJH!MTB"
        threat_id = "2147847355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "yqbvvlm scctuimh ybqhox jabt fhjpomxk rch yjje qekd hbwfc ineyy" ascii //weight: 1
        $x_1_2 = "aovbc emu tps cldr tmphbxc" ascii //weight: 1
        $x_1_3 = "xbisv dlrblpomi crvnqqnxy hpj" ascii //weight: 1
        $x_1_4 = "choej abjdn xnp obqjsq ypd bmihjxgxv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_GMH_2147888911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.GMH!MTB"
        threat_id = "2147888911"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b cf 8a 1c 01 8d 50 56 8a cb e8 ?? ?? ?? ?? 0f be f0 33 d2 0f be c3 03 45 fc 6a 19 59 f7 f1 8b 45 fc 8b ca d3 e6 8b 4d f8 03 ce 40 89 4d f8 89 45 fc 39 47 10}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_GMH_2147888911_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.GMH!MTB"
        threat_id = "2147888911"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 ec 40 89 45 ec 83 7d ec 03 ?? ?? 6a 01 8d 45 f8 50 6a 01 68 68 35 00 00 6a 00 68 32 2c 00 00 68 b9 38 00 00 e8 ?? ?? ?? ?? 83 c4 1c}  //weight: 10, accuracy: Low
        $x_1_2 = "XEzOZDUTXftEUBHjV" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_A_2147906217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.A!MTB"
        threat_id = "2147906217"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 07 8b 48 04 8a 44 39 40 8b 4c 39 38 88 45}  //weight: 2, accuracy: High
        $x_2_2 = {8b 4d e8 8b 45 ?? 89 1c 88 ff 45 e8 39 75 e8}  //weight: 2, accuracy: Low
        $x_2_3 = {8b c7 8d 4d ?? 33 c6 99 52 50 e8 ?? ?? ?? ?? 59 59 83 78}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_B_2147906310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.B!MTB"
        threat_id = "2147906310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {d3 e0 33 45 ?? 99 89 45}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 06 85 c0 0f 99 c2 8b 0f 8b 06 2b ca 33 d2 3b c8 8b 06}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_C_2147906314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.C!MTB"
        threat_id = "2147906314"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff ff 99 f7 bd ac ?? ff ff 03 95 24 ?? ff ff 03 95 e0 ?? ff ff 8b c2 99 89 85 30}  //weight: 2, accuracy: Low
        $x_2_2 = {d3 e0 0b 85 fc ?? ff ff 99 89 85 18}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_D_2147907100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.D!MTB"
        threat_id = "2147907100"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {59 59 89 06 89 46 ?? 8d 04 98 89 46 ?? 89 7d fc 8b 0e 8b c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_E_2147907200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.E!MTB"
        threat_id = "2147907200"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 fc 40 89 45 fc 83 7d fc 02 7d ?? 8b 45 fc c7 84 85 88}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_EC_2147908398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.EC!MTB"
        threat_id = "2147908398"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {33 d2 8b c6 6a 34 59 f7 f1 8b 45 08 8b 0c b3 8b 14 90 8b c1 23 c2 03 c0 2b c8 03 ca 89 0c b3 46 3b f7 72 dc}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_EC_2147908398_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.EC!MTB"
        threat_id = "2147908398"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 14 01 8d 48 11 8a c1 22 c2 02 c0 2a c8 0f be c2 03 45 fc 02 ca 0f be f1 33 d2 6a 19 59 f7 f1 8b 45 fc 8b ca d3 e6 8b 4d f8 03 ce 40 89 4d f8 89 45 fc}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_RM_2147908627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.RM!MTB"
        threat_id = "2147908627"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 75 08 8d 45 d4 89 5d fc 56 6a 00 68 8c 2b 00 00 68 a7 00 00 00 50 ba 12 0c 00 00 b9 8d 6b 00 00 e8}  //weight: 1, accuracy: High
        $x_1_2 = {49 49 23 c8 74 ?? 33 c0 40 8b ?? ?? ?? ?? ?? d3 e0 8b ?? ?? ?? ?? ?? 2b c8 89 0e 00 d3 e0 8b ?? ?? ?? ?? ?? 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Neoreblamy_RM_2147908627_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.RM!MTB"
        threat_id = "2147908627"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 04 58 d1 e0 8b 84 05 ?? ?? ff ff 48 6a 04 59 d1 e1 89 84 0d ?? ?? ff ff 6a 04 58 d1 e0 83 bc 05 ?? ?? ff ff 00 7c 72}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 75 14 ff 75 08 68 99 27 00 00 68 2c 0d 00 00 ff 75 0c 6a 00 68 67 11 00 00 68 20 64 00 00 ff 75 10 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_RN_2147909394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.RN!MTB"
        threat_id = "2147909394"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {51 51 68 cf 00 00 00 68 24 32 00 00 51 52 51 51 68 ec 48 00 00 ff 75 0c 8d 55 fc b9 e7 1c 00 00 ff 75 08 e8 0a 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_RP_2147909710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.RP!MTB"
        threat_id = "2147909710"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c0 2a c8 0f be c2 03 45 fc 02 ca 0f be f1 33 d2 6a 19 59 f7 f1 8b 45 fc 8b ca d3 e6 8b 4d f8 03 ce}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_RS_2147909835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.RS!MTB"
        threat_id = "2147909835"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {21 45 f8 ff 31 8b 45 fc 83 c0 0c 68 44 b3 06 10 89 45 fc ff 30 6a 03 68 51 03 00 00 56 e8 8d fd ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_RS_2147909835_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.RS!MTB"
        threat_id = "2147909835"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f be f0 33 d2 0f be c3 03 45 fc 6a 19 59 f7 f1 8b 45 fc 8b ca d3 e6 8b 4d f8 03 ce 40 89 4d f8 89 45 fc 39 47 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_RV_2147910504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.RV!MTB"
        threat_id = "2147910504"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 75 0c 8b c2 ba 03 0f 00 00 68 7c 4b 00 00 ff 75 10 68 3e 24 00 00 6a 01 51 68 eb 1b 00 00 ff 75 08 8b c8 68 d3 5c 00 00 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_RU_2147912149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.RU!MTB"
        threat_id = "2147912149"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c4 04 89 45 d8 8b 45 d8 89 45 e4 33 c9 8b 45 e0 ba 04 00 00 00 f7 e2 0f 90 c1 f7 d9 0b c8 51}  //weight: 1, accuracy: High
        $x_1_2 = {6a 04 58 c1 e0 00 8b 84 05 94 fb ff ff 40 6a 04 59 c1 e1 00 89 84 0d 94 fb ff ff 6a 04 58 c1 e0 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Neoreblamy_RA_2147912584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.RA!MTB"
        threat_id = "2147912584"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 4c 24 10 57 8b c2 99 6a 18 5b f7 fb 89 5c 24 24 8b f0 8b 45 08 2b c1 89 74 24 20 99 8b fe f7 fb 89 44 24 1c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_RB_2147912585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.RB!MTB"
        threat_id = "2147912585"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 4d f8 57 8b c2 99 6a 18 5b f7 fb 89 5d e8 8b f0 8b 45 08 2b c1 89 75 ec 99 8b fe f7 fb 89 45 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_RB_2147912585_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.RB!MTB"
        threat_id = "2147912585"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 7d 08 01 75 1c e8 ?? ?? ?? ?? 99 6a 03 59 f7 f9 42 42 69 c2 e8 03 00 00 50 ff 15 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_RR_2147913105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.RR!MTB"
        threat_id = "2147913105"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 16 59 33 d2 8b c6 f7 f1 8b 45 08 8b 0c b3 8b 14 90 e8 cc ff ff ff 89 04 b3 46 3b f7 72 e1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_RC_2147914155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.RC!MTB"
        threat_id = "2147914155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 8b c6 6a ?? 59 f7 f1 8b 45 08 8b 0c b3 8b 14 ?? 8b c1 23 c2 03 c0 2b c8 03 ca 89 0c b3 46}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_RD_2147914332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.RD!MTB"
        threat_id = "2147914332"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d3 f8 33 45 dc 99 89 85 58 ff ff ff 89 95 5c ff ff ff ff b5 5c ff ff ff ff b5 58 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_RD_2147914332_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.RD!MTB"
        threat_id = "2147914332"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c0 8b cf 40 d3 e0 85 c2 0f 95 c2 85 c3 0f 95 c0 8a c8 0a c2 22 ca 0f b6 c0 33 d2 84 c9 0f 45 c2 8b 55 fc 03 f6 0f b6 c8 0b f1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_RE_2147914503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.RE!MTB"
        threat_id = "2147914503"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d fc 8b 14 01 83 c2 01 6b 45 f4 74 8b 4d fc 89 14 01 6b 55 f4 74 8b 45 fc 8b 0c 10 83 e9 01 6b 55 f4 74 8b 45 fc 89 4c 10 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_ANR_2147915253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ANR!MTB"
        threat_id = "2147915253"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 9d c1 81 f9 ed 1a 10 88 1b c9 33 d2 41 3b c1 0f 9f c2 69 45 d4 f9 47 00 00 33 c9 3b d0 0f 9e c1 81 e9 02 fc 00 00 f7 d9 1b c9 41}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_ANE_2147915274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ANE!MTB"
        threat_id = "2147915274"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "yBIwEaeeOUFbOrfMOaTDGlDoVKox" ascii //weight: 1
        $x_1_2 = "ABSMvNsiwcnhJUvFOnXKIRaJegDnQt" ascii //weight: 1
        $x_1_3 = "xcWkWuCwPYedugCbhGhLaEDWQfjoD" ascii //weight: 1
        $x_1_4 = "wjUgAeICjnTbiETALhEcewWAVCSmE" ascii //weight: 1
        $x_1_5 = "ncCNRLWFNHQnprtku" ascii //weight: 1
        $x_1_6 = "ZpTzcFsEKixxexqjaFPdter" ascii //weight: 1
        $x_1_7 = "SOVeUZBI" ascii //weight: 1
        $x_1_8 = "ptZbHSKnbmPUipEFImG" ascii //weight: 1
        $x_1_9 = "pZiEOznMsTgddhwU" ascii //weight: 1
        $x_1_10 = "tBNyzIIYTDcQRWFVko" ascii //weight: 1
        $x_1_11 = "wwrfstaGXSIxkdfYEJiXATBTI" ascii //weight: 1
        $x_1_12 = "KujrBSOwGDTBEiKBolTPwL" ascii //weight: 1
        $x_1_13 = "wvUAyJADstRsQeDcv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_AO_2147915510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.AO!MTB"
        threat_id = "2147915510"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cdZfAoUwymYcKDyvhWObYsLdWyGPBU" ascii //weight: 1
        $x_1_2 = "cTOZFJHdxLPvueNOjClAQUNpfnnX" ascii //weight: 1
        $x_1_3 = "fOOufmGnqIABQpnYgYPqmOUfOrfQ" ascii //weight: 1
        $x_1_4 = "ueNqDjihFZbmFOGuvlbDfQGbLoWb" ascii //weight: 1
        $x_1_5 = "HwXFfSSyciqwBLjkWOgyXXsbTAaWNY" ascii //weight: 1
        $x_1_6 = "zlXBWEEaHNtxtRiVRNwgNZrnkwZWS" ascii //weight: 1
        $x_1_7 = "zlkVVIEOIbJHVdDepuDDcdQZgGCsc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_RF_2147915940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.RF!MTB"
        threat_id = "2147915940"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 f8 00 00 00 68 db 19 00 00 68 fd 2a 00 00 68 09 49 00 00 6a 01 6a 00 ff 75 8c ff 75 88 68 aa 22 00 00 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_AQ_2147916403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.AQ!MTB"
        threat_id = "2147916403"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QqrbfpDhlOMDQIzPxGHEJjOEaEhEa" ascii //weight: 1
        $x_1_2 = "pFUJnCzvLTsCVGkWzZDytUHxXgZdF" ascii //weight: 1
        $x_1_3 = "VfHcZjffZsTPdTWShrXeKheBahHgx" ascii //weight: 1
        $x_1_4 = "nHsjZlpxnSCMsasgVAJto" ascii //weight: 1
        $x_1_5 = "KUtfkWcTyzFQItjiUQIvcT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_ASA_2147916960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ASA!MTB"
        threat_id = "2147916960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BnelqbRvMtoEWPBUbgyubHyBJpJGEB" ascii //weight: 1
        $x_1_2 = "huXkwzeouonixlmWz" ascii //weight: 1
        $x_1_3 = "fwLYDUZUcoYeDFYkBoOVhNomTGOLaPnovN" ascii //weight: 1
        $x_1_4 = "mgnVPcrLihAGzMbVZAmVVBRecVyJ" ascii //weight: 1
        $x_1_5 = "YgymvWYlVhFCkgxqodqHMevBTNOO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_ASB_2147916961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ASB!MTB"
        threat_id = "2147916961"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hlfpCkgPKUJwxaArcRynZn" ascii //weight: 1
        $x_1_2 = "ptEHhqDcuaijwKQAeeYgEjZvhvfO" ascii //weight: 1
        $x_1_3 = "vYFKIDBcKbGTUknkkgNQMDqoOupLvo" ascii //weight: 1
        $x_1_4 = "xooBipYNfxLanhGgoHjCRHePLeGYR" ascii //weight: 1
        $x_1_5 = "AVTXRUINmLablxSmabnNsiBjskRCawCBof" ascii //weight: 1
        $x_1_6 = "SSoQHjdPlTKeWUqKgKhhwiE" ascii //weight: 1
        $x_1_7 = "kBwtnkHUtGIjlLdydzwvxuwcMoRDTA" ascii //weight: 1
        $x_1_8 = "WusPebppWWJQogPWyGjlyoAaxpyM" ascii //weight: 1
        $x_1_9 = "gvasaWXLdpADUwuuBfrbsyQvyWVRtX" ascii //weight: 1
        $x_1_10 = "fDuONwLoggshmDuyBScLaOwLyEkT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Neoreblamy_AP_2147917040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.AP!MTB"
        threat_id = "2147917040"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 8b ec ff 75 18 68 1b 03 00 00 6a 01 ff 75 08 68 4c 28 00 00 ff 75 14 68 f2 28 00 00 ff 75 0c 68 e8 4a 00 00 ff 75 10 68 c9 38 00 00 6a 01 e8 ?? ?? 00 00 83 c4 30 5d c3}  //weight: 2, accuracy: Low
        $x_2_2 = {c7 85 7c ff ff ff 10 b9 13 17 c7 85 dc fb ff ff 5c 46 f2 0b c7 85 88 ea ff ff a9 51 03 ec c7 85 08 f4 ff ff 87 59 b0 91}  //weight: 2, accuracy: High
        $x_1_3 = "gbITNPwbYsMlaGlDWnIXgBGgFWsHVtBN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_ASC_2147917058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ASC!MTB"
        threat_id = "2147917058"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WdlTxhAtRfKoKSZdNyLmDnBzBelqi" ascii //weight: 1
        $x_1_2 = "DMDqrlyxTQylPBDEgqfAkEEZsdBtz" ascii //weight: 1
        $x_1_3 = "YiTTKEUzdDOLNtOJNHVLeHvmxOrdM" ascii //weight: 1
        $x_1_4 = "GUkKeJPikEzIIvnSHmANHAeju" ascii //weight: 1
        $x_1_5 = "mukxNgRSyQfGtEVAiHZDwZHScVtCoDmkza" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_ASD_2147917222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ASD!MTB"
        threat_id = "2147917222"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pCkGCAubNKjddBVItuoYywgzA" ascii //weight: 1
        $x_1_2 = "wiozjQjYSkndZnqvidutACSPzUK" ascii //weight: 1
        $x_1_3 = "usbnHLcPbBIoBznsEdJUQazWKvqmiGOsuMcjUhrae" ascii //weight: 1
        $x_1_4 = "SXLmHPFaEjbmjdnwOUzWCYIdbsXEpi" ascii //weight: 1
        $x_1_5 = "aGFuBOSwoGeuSNlEXcNPVjhnSAf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_ASE_2147917226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ASE!MTB"
        threat_id = "2147917226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IgMBNivjHYupogbdsAMKilNhRwYanhaT" ascii //weight: 1
        $x_1_2 = "gSgQVeRMFFeFgLQNLzGgltmQBLM" ascii //weight: 1
        $x_1_3 = "KBdcsryyIVGUgFnqHoaMkCXrYzDYQnDdJJx" ascii //weight: 1
        $x_1_4 = "aaImRLyonHCpCqUpbkXTPxCvn" ascii //weight: 1
        $x_1_5 = "CiTXfuUZYdbPXmNnaeMDELdajjiM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

