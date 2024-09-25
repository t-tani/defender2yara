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

rule Trojan_Win32_Neoreblamy_ASF_2147917655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ASF!MTB"
        threat_id = "2147917655"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EfyexHFAtsJpVktMQEGNVbUbuxUaWP" ascii //weight: 1
        $x_1_2 = "BrRmXFrVhiMBbrDGFIxVCgzkpifA" ascii //weight: 1
        $x_1_3 = "XUofKoXBFJaHTBGlDRwTdCUlKrSCCnHjKA" ascii //weight: 1
        $x_1_4 = "ZtNddFPvPSJBvQtOzXowOTcJiGxeX" ascii //weight: 1
        $x_1_5 = "wmVckGkcwuXuPVtDAZNhkGbRQdgcvJ" ascii //weight: 1
        $x_1_6 = "VYUxvsbfjcwSWkpIQWSoGXffvtHx" ascii //weight: 1
        $x_1_7 = "wiNIHRUBtpkAqQvvDWUsmICWwKzIjB" ascii //weight: 1
        $x_1_8 = "mlwoEKCSShfWjNSJLkbLGRgfBCNT" ascii //weight: 1
        $x_1_9 = "heqUxnuLvDWrMaVLDYaUuoPlazbkGGNSov" ascii //weight: 1
        $x_1_10 = "KJSDFVppHwOJYqMLXupmSMNKwHoXSgPRMa" ascii //weight: 1
        $x_1_11 = "qCYbfFYmGYIsAdzSijUmndDKrvwRpHvFVkf" ascii //weight: 1
        $x_1_12 = "JUsPSmAeeWvGBKyqGYCDUOmexPJLheFB" ascii //weight: 1
        $x_1_13 = "xxuZqXVxcPiLXvMQSqpAHnbcEOHybUrXXrJTTgJjICeoaDxQqtP" ascii //weight: 1
        $x_1_14 = "QnTYNRhBkghuQcMgQeMhccZyLrriYujwztRjQsxUl" ascii //weight: 1
        $x_1_15 = "ygORzCoMvVWORxIVYGTnemSiQQMdhCqaRLobn" ascii //weight: 1
        $x_1_16 = "xzakHXTpeHswQftaFtvwLlFsrgRIapnFO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Neoreblamy_ASG_2147917916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ASG!MTB"
        threat_id = "2147917916"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wWAXSQVokUkxfzAQGSqXAfxkTMIyyUVF" ascii //weight: 1
        $x_1_2 = "bbOzeddgpxCZdsAviIewTdZhdnfskamHnGNJJecag" ascii //weight: 1
        $x_1_3 = "qaNJTvjPYdEFgUGcVPKBoQlKIwRyZmH" ascii //weight: 1
        $x_1_4 = "aoQTGTqbmXvIuYDlpdIjmhURTYCTGQqQjU" ascii //weight: 1
        $x_1_5 = "yklwZmhLZnxkjHRvUBlQAWwKPgehyi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_ASI_2147918292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ASI!MTB"
        threat_id = "2147918292"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XNvNtkzciTWOmggiaBIdDAlceQZ" ascii //weight: 1
        $x_1_2 = "ulMuaKXCZMmFDqzTJixBpSVcyAVtvRrIiwYJWGPhTGftjQLEIYz" ascii //weight: 1
        $x_1_3 = "vnaeifFmfoOoeEmeWtBPoHDDPpZXPFz" ascii //weight: 1
        $x_1_4 = "UeTdQEmCicCDAEKkWdqGLBbTuPzHecJWMxOsS" ascii //weight: 1
        $x_1_5 = "VRVZcpiffsHAnNGQFiJBRLcnaoZwFdCBke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_SPSH_2147918396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.SPSH!MTB"
        threat_id = "2147918396"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "BjsdKzpmuZzKroK" ascii //weight: 2
        $x_1_2 = "LuFOqzyiXOpePkCtxhekGFCWu" ascii //weight: 1
        $x_1_3 = "VcwcOZFSwoRBZgutnysa" ascii //weight: 1
        $x_1_4 = "JXCLnAPqSOOZqAxQZkpz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_GPA_2147918504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.GPA!MTB"
        threat_id = "2147918504"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RywjRURvTHxFkk" ascii //weight: 1
        $x_3_2 = "EkDmRTHVLqBoJvetwcsLjMw" ascii //weight: 3
        $x_5_3 = "FgbdIYubCAnaElbGjlq" ascii //weight: 5
        $x_7_4 = "qQptxMomkNymuOqXMrWXba" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_GPB_2147918595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.GPB!MTB"
        threat_id = "2147918595"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UovlTegQiyFNbzmPA" ascii //weight: 1
        $x_3_2 = "wQMwRbVHfUeLriTfv" ascii //weight: 3
        $x_5_3 = "DfTspRbZGckHHfmYCTasYfc" ascii //weight: 5
        $x_7_4 = "yGFpMKNyfMbkArLapy" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_ASJ_2147918602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ASJ!MTB"
        threat_id = "2147918602"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hSzACesAwpbbueBXfUqVGbJ" ascii //weight: 1
        $x_1_2 = "YfWeNVNHffsqLGqsdfrjNSMdYOdxUxRp" ascii //weight: 1
        $x_1_3 = "BaEzsQMEYTCgmHxYMJRcPNowwe" ascii //weight: 1
        $x_1_4 = "yVrCadYijLVpqhasTZnxdkymGYJRq" ascii //weight: 1
        $x_1_5 = "BkBdffuSxHbvJJTmcIUzggrnrequu" ascii //weight: 1
        $x_1_6 = "vaDHEazMJLRAMrLcLtgsUSdjEAe" ascii //weight: 1
        $x_1_7 = "xpwXDpGMLsWYXMxRsNYFCqy" ascii //weight: 1
        $x_1_8 = "RwIatgpQJgAKXrGpcFztVbPwWiiQDNLn" ascii //weight: 1
        $x_1_9 = "qqKwMOvdaLThwsGJclnlQnpCopDPwfANlfJLGSn" ascii //weight: 1
        $x_1_10 = "ElNBADQrwrqICtdMdeOoArACeci" ascii //weight: 1
        $x_1_11 = "nDyCmUzxUXkXeCugZwmndRBFXoOry" ascii //weight: 1
        $x_1_12 = "abKQMgWQvJYTQqtGNzUlrwd" ascii //weight: 1
        $x_1_13 = "CiTXfuUZYdbPXmNnaeMDELdajjiM" ascii //weight: 1
        $x_1_14 = "ZiegyTNCQGjTGtNAcKqIhksvrACORgwhRjhN" ascii //weight: 1
        $x_1_15 = "gySLGMvOMDBCrfnvEeoKpHYxOKwGQDB" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Neoreblamy_ASK_2147918708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ASK!MTB"
        threat_id = "2147918708"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bjJlRrINAtkRxmkveI" ascii //weight: 1
        $x_1_2 = "UCAhtKLUxZoGNNamSqpZeowxCKDOJ" ascii //weight: 1
        $x_1_3 = "dMehrlqREhvaVsLbIoliaeQaVnfuLnXKdkgKG" ascii //weight: 1
        $x_1_4 = "pyywsczsDTsrheFVGysPJjEIEDiUyKFlRvn" ascii //weight: 1
        $x_1_5 = "mzIkskJpvWuBKQbFvfAVBsHLukBinuHuvPIYgnY" ascii //weight: 1
        $x_1_6 = "TyPInlwHIHVXhrsbftaCyKFtXHFaQGkfveRONbNyGT" ascii //weight: 1
        $x_1_7 = "pxmCpAmYbayldEalIIWjTDVCdeXLUtKWnDKOt" ascii //weight: 1
        $x_1_8 = "DnsOtBmBPQOyaeXFNGQbbvGcjsYXVWrWLY" ascii //weight: 1
        $x_1_9 = "NhtwyrpzsInnYqsCMdHYSxWCkznHLl" ascii //weight: 1
        $x_1_10 = "GVYlugxPlVWpFFDDhUqNEpEPJYkYIxpVqY" ascii //weight: 1
        $x_1_11 = "OBnCasvPIwxWLAsmTqOjDRfNoUWehBAbQwHM" ascii //weight: 1
        $x_1_12 = "ePeyqKssuOoXySycqOYbPHEUtOelPaAWvfiniCg" ascii //weight: 1
        $x_1_13 = "aySaNELeREqJUlvwYHKfKrevSYBvwk" ascii //weight: 1
        $x_1_14 = "EOHbhWtjsCFqQHPPVpvXOkbKcykOiX" ascii //weight: 1
        $x_1_15 = "JgaSerfGgYZpJmlcmWcujQXJHWZorxnYsZKyp" ascii //weight: 1
        $x_1_16 = "CxOuzAoSucgGgmbSqwtZjsTtRatboLosXKHDByT" ascii //weight: 1
        $x_1_17 = "GFdpomHQZcPUcXXFBsspLRyOmzgd" ascii //weight: 1
        $x_1_18 = "qtiRKADNrMPrxaYZuQSLahCqgzIliNbXKU" ascii //weight: 1
        $x_1_19 = "tdEnxALSaBBQNKUitmrholsbpzetm" ascii //weight: 1
        $x_1_20 = "JlTgsSsEDMgPixUnbnPzmEvxQOpFS" ascii //weight: 1
        $x_1_21 = "SmaOGoacGjbZLWCnvJYPMOpttZitmj" ascii //weight: 1
        $x_1_22 = "KzLfTlOTgoLMlaIBCHWmdyKymAfAIVmmcy" ascii //weight: 1
        $x_1_23 = "mrbBgThteSVFYRXIQYVkxzjBNPghVEQmIy" ascii //weight: 1
        $x_1_24 = "CieKwQmZzGDPnDIovXzAYrLPalbLQWUlcPty" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Neoreblamy_ASL_2147918978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ASL!MTB"
        threat_id = "2147918978"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jRhkTfgSEqQGqcnMbYHRbyMyMSNKjU" ascii //weight: 1
        $x_1_2 = "UvJcTAgHWCyDqCJtKgiKsaxWgxEgVN" ascii //weight: 1
        $x_1_3 = "ESXQoeXEjSFdZcFHNwNJuFMoWWrxYBXanlsyH" ascii //weight: 1
        $x_1_4 = "qeXYDiNcAXbtiUKnwMbsFDjYWbglUdlXjv" ascii //weight: 1
        $x_1_5 = "SzckAEMmSQwcbgBOMknWXjFVeGeSOXxgku" ascii //weight: 1
        $x_1_6 = "OjrrKlScCkKhJxwTzygzibOPurXmkVwbclLxB" ascii //weight: 1
        $x_1_7 = "chDfqpgmgZrFqTFExXfGtoTtmfmLatIZdaSzcZLsjxxYYNrBXkJ" ascii //weight: 1
        $x_1_8 = "RaGDmEqNXKpoPmxiTPANRlDqt" ascii //weight: 1
        $x_1_9 = "OoeMNmuWPnYUnVlElXgRuaUKcIDhZa" ascii //weight: 1
        $x_1_10 = "HVRVuZSxgGwXJAhleJQlSYbMAcKBtu" ascii //weight: 1
        $x_1_11 = "PTpPKWjlfdDeGpNmTFQCZnoQsdyASgQNmt" ascii //weight: 1
        $x_1_12 = "BCiZXMuPyRnwvEKmjiSyGRnxpkCShIzlQVZuixKDAw" ascii //weight: 1
        $x_1_13 = "MCLwhjlFnNFRtHDaNjTvnGbaoAYa" ascii //weight: 1
        $x_1_14 = "xBzXsMVaqaqMxcjuhCtZMHIwjzuBECWHuV" ascii //weight: 1
        $x_1_15 = "YfsEYMqDjdtjyRAElUAPwpXEjTyKbFq" ascii //weight: 1
        $x_1_16 = "PtQPzdfDgYsquoaUWkHGsguEYTxlLjnkvKmrPGw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Neoreblamy_ASM_2147918992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ASM!MTB"
        threat_id = "2147918992"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ZKldSKBJIGRgTJbbpdWgJqmeEdruoa" ascii //weight: 1
        $x_1_2 = "rsmZaGShKgCJDDiRiwVpxxLTQoRG" ascii //weight: 1
        $x_1_3 = "RTqFpTODZNplMwyuzDYAwHdZhWyBqHLtFB" ascii //weight: 1
        $x_1_4 = "yQEsqaBkvMmFwRdZQzGDVcFAsaJFJSlSiPOIDTwUu" ascii //weight: 1
        $x_1_5 = "OnaXuqSmkpnSXzGdYTXixxNHIdBQwt" ascii //weight: 1
        $x_1_6 = "ZOiIqlVZDQmAteNGrMJKnZYvIMnmZiSUuJ" ascii //weight: 1
        $x_1_7 = "HzxAfUljHQkooUsnfougjjHinVLRZeyEhHfmuJNVoW" ascii //weight: 1
        $x_1_8 = "cDwygoNgSJgpBkklllJyXyzmKHfYkvgPTOvOrskwl" ascii //weight: 1
        $x_1_9 = "FTtJkMMhPFCBZSlsBRklUgMMqoAHbLyqUe" ascii //weight: 1
        $x_1_10 = "QJHuhZGzhDHCuPyBTmWtyvouJodVzmYGMcUJzpovVX" ascii //weight: 1
        $x_1_11 = "rrLlrMMLmFYoTpqlGfMszKjeIuqFojjUxKoemGpOuKiAeVyDFOs" ascii //weight: 1
        $x_1_12 = "CGUYRiRQwnWsNOCdxoTjbVOke" ascii //weight: 1
        $x_1_13 = "thgtLTKrcZueHwrITOIBtHBLIQHrLp" ascii //weight: 1
        $x_1_14 = "LCTOvdkBeRhsElDJRoOCQQdoGMBc" ascii //weight: 1
        $x_1_15 = "jgfhZelmLnaUcGVhyCIoApHYUYOCGZEDieGPjCv" ascii //weight: 1
        $x_1_16 = "kUQwTClIhBAWMhbqkYuiqfXXCuxyKCYLIYHXeUOIT" ascii //weight: 1
        $x_1_17 = "KeMXwtxNEdIdUnsxOoXzjOqLgMWqahseroWcYXROjQwYAfscgDf" ascii //weight: 1
        $x_1_18 = "bPwmTBTnnMTfmkWSERHcRHBSuxqb" ascii //weight: 1
        $x_1_19 = "DiyfhRqaXYLyGuOCQCZffVdNDgvBkqbwiMOSw" ascii //weight: 1
        $x_1_20 = "NFoiuOeHzShSYLfGSzeJXrFBkfhkCqnErpjgJzJBz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Neoreblamy_ASN_2147919078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ASN!MTB"
        threat_id = "2147919078"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YIgmVIuxQEkNMpeWGSHBiRYHaxqkIj" ascii //weight: 1
        $x_1_2 = "DDntGvAMAXrGKHjwmaJeLteSpWUifn" ascii //weight: 1
        $x_1_3 = "SzdGaitnikRUtDHhbfsqPQDnCBWQpSiZLkKiP" ascii //weight: 1
        $x_1_4 = "kxniPSOrccXdCfTBsAVthdzTMVGFrOSaKYjNnnQ" ascii //weight: 1
        $x_1_5 = "RwFFGEhZuioiaMVqzTxVfZxHgsJYRI" ascii //weight: 1
        $x_1_6 = "rKofcrccUwiKiekrDtqoLAZaIEkZUaTIRP" ascii //weight: 1
        $x_1_7 = "QyQRJCUIkLBVOgdkGsodfkGDgMXqgFqYxdVXw" ascii //weight: 1
        $x_1_8 = "REHxJRuVggpwudhwotmVWHNwKHxJTdKeBY" ascii //weight: 1
        $x_1_9 = "qVTXJdjjboVCulckmeUMRMRmyfTNkh" ascii //weight: 1
        $x_1_10 = "uWhvkYhOOxHtbmPQUfcheEpqAoqB" ascii //weight: 1
        $x_1_11 = "oGMWVffHripxQheexPAhVcWZvrmEduGMJevs" ascii //weight: 1
        $x_1_12 = "BNbeUfNaCOHDAqUvTxrtfKbvXMhESekClnyxWIBHb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Neoreblamy_ASO_2147919710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ASO!MTB"
        threat_id = "2147919710"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zPMSxSdxMhQYRzzDGTYHGCXeiVBzCi" ascii //weight: 1
        $x_1_2 = "rWzrvQYZWWbnsSzUAlFQjeLIpSCVRGyZjb" ascii //weight: 1
        $x_1_3 = "ZtMgnvwAqYJExMiZFkVdpMSsLdgKqKjbXp" ascii //weight: 1
        $x_1_4 = "AUxAbyoPMdNdaKZZAVivvZATkCTxvyJdrZSqDhnuMn" ascii //weight: 1
        $x_1_5 = "WeCLxQzoxGZHZGVNMncrBWAeKvnjNM" ascii //weight: 1
        $x_1_6 = "wANpwFvqBLdQbHZkOAuiLmXGuqtnvtluLC" ascii //weight: 1
        $x_1_7 = "UOriwOPGiBftlRlKocEqjFrHauAaLlyRRXEh" ascii //weight: 1
        $x_1_8 = "pnIIPOAIFSZSdNHkUretDCqOucMVJdImCsCjZOY" ascii //weight: 1
        $x_1_9 = "zCUrdpyiMNnWZQPkQBsIIZnAGJmWLE" ascii //weight: 1
        $x_1_10 = "MMznjIcSNfVzlZILXwYPhyrkdPRJISoGUZ" ascii //weight: 1
        $x_1_11 = "yijWjhXPOZJFdpZbYcJEcBMSEbqmrbUKKwHiqVZzgu" ascii //weight: 1
        $x_1_12 = "eiegIaJjiQENryrszwsgCmujqRzAWvyeMvV" ascii //weight: 1
        $x_1_13 = "NJEVRWUOKAYRVmLfwFrmsuNmGyiI" ascii //weight: 1
        $x_1_14 = "iRzTEYDEGDlCXixoVRKdTzhQeqvxXSPwxb" ascii //weight: 1
        $x_1_15 = "nxzAqxBAydWjWAXNlDhVpzXVPEcQDJtpjiudtuQztL" ascii //weight: 1
        $x_1_16 = "VtXsscJrLfsBJuohLtAKeEVyUgjGpdIAgD" ascii //weight: 1
        $x_1_17 = "OZSuRpJvOliamVUZqxKTzYDWjhEQAm" ascii //weight: 1
        $x_1_18 = "GOOKjiPwEqpxfswyIGkOdaNWzLTWDoOaUz" ascii //weight: 1
        $x_1_19 = "YoueDBllAEQZCYanrepQoaqDhzFttIoNSGLHq" ascii //weight: 1
        $x_1_20 = "bESGkGqlRQMSTkqHNWLUFtsZvNLYlDZJPUzIZgg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Neoreblamy_GPC_2147919741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.GPC!MTB"
        threat_id = "2147919741"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VrgcifQlZtruzgMnM" ascii //weight: 1
        $x_3_2 = "KjdcbCqcaSTusNSJWecwpJu" ascii //weight: 3
        $x_5_3 = "IWiwjYkoJvQnzeWAz" ascii //weight: 5
        $x_7_4 = "dTiHdTJvPxdLYR" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_ASP_2147920000_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ASP!MTB"
        threat_id = "2147920000"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ocfUGNaeCiFrsSfMqrTwYwugHygKsM" ascii //weight: 1
        $x_1_2 = "HuhUplMHuyvTPOZokFzTYcSUzSqWQ" ascii //weight: 1
        $x_1_3 = "WxGvokfBFJczLOiYIzaHShTcgXVCkSmeit" ascii //weight: 1
        $x_1_4 = "IbxXaedKzAaePasdxQrpWgfvZUFIcwHRyeudNxr" ascii //weight: 1
        $x_1_5 = "eeZmocAdsGCCRcWzDXKqKEghRHml" ascii //weight: 1
        $x_1_6 = "adkHqKoQeUFITBSEnAcRkfZbmoQbZKsNgO" ascii //weight: 1
        $x_1_7 = "trcnKJjYmHXbbWDpNtufMqTWUmCYLvomsjEt" ascii //weight: 1
        $x_1_8 = "mWaKNPEqWLYRyLDrGdqixHYyKzKahxyhivZwklQZt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Neoreblamy_CZ_2147920196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.CZ!MTB"
        threat_id = "2147920196"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 e0 03 45 f4 c6 00 eb 0f b6 45 ff 48 48 8b 4d e0 03 4d f4 88 41 01 0f b6 45 ff 03 45 f4 89 45 f4 eb}  //weight: 2, accuracy: High
        $x_1_2 = "GPvsPFqwtsMlKOQqZUIYBOtBqwdl" ascii //weight: 1
        $x_1_3 = "SOrGmWZrCZSgmEBXdKNZLEoOwFMU" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Neoreblamy_BG_2147920597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.BG!MTB"
        threat_id = "2147920597"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "yGggPgNTrmQPzLuMXzKIpgmzwtZLtVYtIL" ascii //weight: 1
        $x_1_2 = "sRdERgnYxbWZcPoUKiiNHxPECYYFc" ascii //weight: 1
        $x_1_3 = "BmjKHsfmNOygCNPKFJVnonpMwSyRpElttxvhnGHQI" ascii //weight: 1
        $x_1_4 = "LUsICGAsgAScYTmjSJRApNmocmLksZbh" ascii //weight: 1
        $x_1_5 = "vxedqDPpCqRUvWSkRKNtOGIUtaOCQmrjGz" ascii //weight: 1
        $x_1_6 = "uEjbMGdofjGDvzxgwjvVfdSTtvGZB" ascii //weight: 1
        $x_1_7 = "wBWKKGKYSnGvwXSQQGEgiNk" ascii //weight: 1
        $x_1_8 = "mwvDOcOUTXrfbMeZCBxXuOJDBcJgwCBVCAVm" ascii //weight: 1
        $x_1_9 = "eDIpMRBZeYmpNRPdcbKaocFmmtktvI" ascii //weight: 1
        $x_1_10 = "OKxRhqpbRNeFACxROwyypgKiNUVKzzsqkg" ascii //weight: 1
        $x_1_11 = "AViSRSIvGFsyPxJROkfiDqb" ascii //weight: 1
        $x_1_12 = "PhtoEyzgYCJHPQDlLfoSACrTCPx" ascii //weight: 1
        $x_1_13 = "kDeQdPCKVQtXDkdwJcHotJBMIaCZzM" ascii //weight: 1
        $x_1_14 = "WriNfHHKLJWPmngvmhQeVjHQwbos" ascii //weight: 1
        $x_1_15 = "AqpKmJPAeoTLMMpbQzwNQItCOGzdXCpENP" ascii //weight: 1
        $x_1_16 = "GaMkAXlBApuPPXjVCUeUmebzsscvFsmbkc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Neoreblamy_ASQ_2147921607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ASQ!MTB"
        threat_id = "2147921607"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dqVISnqSpPrYCQEBUwMmCdmyDQYXEt" ascii //weight: 1
        $x_1_2 = "AsspQwpfLaemUWBPYMpvNXsNunlDFA" ascii //weight: 1
        $x_1_3 = "AguFwjhgOuoeLNskmOhIFsByVdxXDgvdiG" ascii //weight: 1
        $x_1_4 = "qqoJuCdamRIPwHUT.dll" ascii //weight: 1
        $x_1_5 = "sgbmAUQgWfeqQdRbWRuFLlrmb" ascii //weight: 1
        $x_1_6 = "ijXDCRihturDIvzKtCwDTuoumUkhVi" ascii //weight: 1
        $x_1_7 = "IkKoNKXebVusyzOktwyfsSYlvOzXihkxGO" ascii //weight: 1
        $x_1_8 = "mqhcjkHfvTpkwQQvsIzffFJPmgGIGucMsGhqfJacVmiRjhrEjbL" ascii //weight: 1
        $x_1_9 = "GdpUExbNERXzZQBJWCMosfmeGInkaK" ascii //weight: 1
        $x_1_10 = "KhxAwwAXLfaulAkmimggHYJZQULDeWyChE" ascii //weight: 1
        $x_1_11 = "qsinHoekOaBVXkEwbWcaroPTSJpvD" ascii //weight: 1
        $x_1_12 = "uGtxnRqAZWtofhxBiCwzXGNsSnZJsSyo" ascii //weight: 1
        $x_1_13 = "wfIozXWgHTUzNcnkpklfTbkxdhgbgU" ascii //weight: 1
        $x_1_14 = "qQWNJaVmfwVFZWutqsMwPGvtUkyf" ascii //weight: 1
        $x_1_15 = "OmtqQTRsSRNxdUZeKMduKXImSzCMcjDmrf" ascii //weight: 1
        $x_1_16 = "WcgVCQGuFUy.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Neoreblamy_ASR_2147921609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ASR!MTB"
        threat_id = "2147921609"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fnWgrHpUOKSPNfRmqNmvtpIZpZOeVIjHaM" ascii //weight: 1
        $x_1_2 = "FhsjawEjwUHblyZTtoVEGjNKpdmcSb" ascii //weight: 1
        $x_1_3 = "hLowcrqMkGJBcftWGyPAyJMZyaQgGcPQgl" ascii //weight: 1
        $x_1_4 = "ALofRioPzJWVIAmiSEWNnrgObJpdIK" ascii //weight: 1
        $x_1_5 = "tkHhGIsAgPFjdRhvMWrKWUVPcOgtDm" ascii //weight: 1
        $x_1_6 = "ARUgqdRXrdMpZkIzvRPUimEKsuBD" ascii //weight: 1
        $x_1_7 = "cEtsVFmswEpBJJzunScRDSVtzHICONXtmA" ascii //weight: 1
        $x_1_8 = "atDrQchkcxiWaaPZQhhxvWSXWfXlMSvXJJhiq" ascii //weight: 1
        $x_1_9 = "SMNdFoXoRiKXKtvMSdPyHQzEqrsFQp" ascii //weight: 1
        $x_1_10 = "RbQdEZctJSbTLppuBcWsIhEVQmddTUzHKu" ascii //weight: 1
        $x_1_11 = "BsdmaJBzuWDgCqZzdxWujAFWluynJ" ascii //weight: 1
        $x_1_12 = "vIbHXabjQgmwoHPibMwJVCDyaSMLhuHYXmTR" ascii //weight: 1
        $x_1_13 = "lVvnXqVUDgAbYYHGxjpvNlKjhTVYrv" ascii //weight: 1
        $x_1_14 = "lxKvGwMnZtGDUMThpxPxfdCOOcdZHjNyyc" ascii //weight: 1
        $x_1_15 = "qjFtWCPlFEMUJAwxRjVBvlgBTJWnL" ascii //weight: 1
        $x_1_16 = "HnGVdPUFoXGgjBQFjTreNaYSsgiOwEp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Neoreblamy_AST_2147921612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.AST!MTB"
        threat_id = "2147921612"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "erOgVBBSwRwVvpSdroEqiffCJEEwRpRoMR" ascii //weight: 1
        $x_1_2 = "SvwPNnGdvHMApnsTeLtjJfNyKdSdIR" ascii //weight: 1
        $x_1_3 = "DVWepnVJZHIFihGOHnnqWLQPBGpoIoYQmlRKJ" ascii //weight: 1
        $x_1_4 = "wflnlRWjUZFRElxCAbZTxkybqfsrCnQfopJKgpdzusyyrFiyXoJ" ascii //weight: 1
        $x_1_5 = "cyecZHCwjDxXsFzOKmeELwBFsQFYeR" ascii //weight: 1
        $x_1_6 = "xYWaDeSyCMKMLRXshPuolKrPyPkeRgGflq" ascii //weight: 1
        $x_1_7 = "aEayDJbzbLvzHXXGFkeEpFgGBcFjt" ascii //weight: 1
        $x_1_8 = "cVwNUrcQzuOxNfkmXVbIUgfCBveBaikMQErsWpDsu" ascii //weight: 1
        $x_1_9 = "ROlLSvSjysRcYvjXMflrNRxTkAqdEZ" ascii //weight: 1
        $x_1_10 = "zRERNEZEgOfQEaPxOdOvnkMEgygw" ascii //weight: 1
        $x_1_11 = "mIewqrCpeZLGMWfMdGZaUtxOHzYI" ascii //weight: 1
        $x_1_12 = "TAxchAwhXckDSovdmgchsOWZZDdbq" ascii //weight: 1
        $x_1_13 = "oMRJlUCQDbHJKCQeunAbOwnhggZp" ascii //weight: 1
        $x_1_14 = "rhIZFUrMtaBlSydyYkDANTYjmRzNeaAoXa" ascii //weight: 1
        $x_1_15 = "EuYRIrNhjiVFVzJTbLepAyyhXxZjFduXmmA" ascii //weight: 1
        $x_1_16 = "rCRuPtKuJcsexDrHkrEdLzbMEWIFStlqAKnRagEAA" ascii //weight: 1
        $x_1_17 = "jeyArBfMBhWFsAwgkSbqCtlYLUZvHW" ascii //weight: 1
        $x_1_18 = "YvJbNxyevgULAeLwMVEXqcoVpUseDfEvrV" ascii //weight: 1
        $x_1_19 = "rMgdZrQYVUKmsDNZwPjFyVxkPNAWB" ascii //weight: 1
        $x_1_20 = "tMPIVpoepMvBgJhKVyMqoYwxLzlBpgGqdiyCg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

