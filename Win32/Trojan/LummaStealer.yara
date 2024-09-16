rule Trojan_Win32_LummaStealer_RPX_2147845170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPX!MTB"
        threat_id = "2147845170"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {32 d3 56 56 80 ea 13 46 d0 ca 46 f6 d2 f7 d6 fe c2 56}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RPX_2147845170_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPX!MTB"
        threat_id = "2147845170"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 b0 6a 40 68 00 30 00 00 8b 4d e4 8b 51 50 52 6a 00 8b 45 cc 50 ff 55 b0 89 45 ec 83 7d ec 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RPX_2147845170_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPX!MTB"
        threat_id = "2147845170"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "os_crypt.encrypted_key" ascii //weight: 1
        $x_1_2 = "Ronin Wallet" wide //weight: 1
        $x_1_3 = "Binance Chain Wallet" wide //weight: 1
        $x_1_4 = "Coinbase" wide //weight: 1
        $x_1_5 = "EnKrypt" wide //weight: 1
        $x_1_6 = "Terra Station" wide //weight: 1
        $x_1_7 = "BitClip" wide //weight: 1
        $x_1_8 = "Steem Keychain" wide //weight: 1
        $x_1_9 = "Hycon Lite Client" wide //weight: 1
        $x_1_10 = "Network\\Cookies" wide //weight: 1
        $x_1_11 = "dp.txt" wide //weight: 1
        $x_1_12 = "45.9.74.78" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RH_2147848410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RH!MTB"
        threat_id = "2147848410"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "localappdata%\\Chro576xedmium" wide //weight: 1
        $x_1_2 = "appd576xedata%\\Ethe576xedreum" wide //weight: 1
        $x_1_3 = "Wallets/Exodus" wide //weight: 1
        $x_1_4 = "localappdata%\\Coinomi\\Coinomi\\wallets" wide //weight: 1
        $x_1_5 = "Wallets/Bitcoin core" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CRIT_2147849271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CRIT!MTB"
        threat_id = "2147849271"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "os_c576xedrypt.encry576xedpted_key" ascii //weight: 1
        $x_1_2 = "Lum576xedmaC2, Build 20233101" ascii //weight: 1
        $x_1_3 = "LID(Lu576xedmma ID)" ascii //weight: 1
        $x_1_4 = "Phys576xedical Ins576xedtalled Memor576xedy:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RPZ_2147852417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPZ!MTB"
        threat_id = "2147852417"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 f3 f6 17 8b c6 8b f3 33 db 33 f6 33 db 33 f6 8b f6 8b f3 33 f3 80 07 75 8b de}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RPZ_2147852417_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPZ!MTB"
        threat_id = "2147852417"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 ec 89 45 f0 8b 4d e4 8b c6 d3 e8 89 45 f8 8b 45 dc 01 45 f8 8b 45 f8 33 45 f0 31 45 fc 8b 45 fc 29 45 e8 8b 45 d4 29 45 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RPZ_2147852417_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPZ!MTB"
        threat_id = "2147852417"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1f 16 5d 91 13 06 07 11 04 91 11 06 61 13 07 11 04 17 58 13 08 07 11 08 11 05 5d 91 13 09 20 00 01 00 00 13 0a 11 07 11 09 59 11 0a 58 11 0a 17 59 5f 13 0b 07 11 04 11 0b d2 9c 00 11 04 17 58 13 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RE_2147888161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RE!MTB"
        threat_id = "2147888161"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 ca 83 e2 03 8a 54 14 08 32 54 0d 04 0f be d2 66 89 14 4f 41 39 c8 75 e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCAK_2147889528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCAK!MTB"
        threat_id = "2147889528"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c8 31 d2 f7 f7 0f b7 44 4d 00 66 33 04 53 66 89 44 4d 00 41 39 f1 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_EB_2147890360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.EB!MTB"
        threat_id = "2147890360"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Add-AppProvisionedPackage -online -packagepath" ascii //weight: 1
        $x_1_2 = "Remove-AppPackage -AllUsers -package" ascii //weight: 1
        $x_1_3 = "Internet Explorer\\Main\\FeatureControl\\FEATURE_BROWSER_EMULATION" ascii //weight: 1
        $x_1_4 = "fyi/Blogtion.msi" ascii //weight: 1
        $x_1_5 = "ppCmdLine=/QN /norestart" ascii //weight: 1
        $x_1_6 = "DownloadFolder=[AppDataFolder]Dino" ascii //weight: 1
        $x_1_7 = "7AD83CDF-AB2B-4A72-A20E-2EDE7913C584" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_NLS_2147891170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.NLS!MTB"
        threat_id = "2147891170"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 91 6c 01 00 00 89 54 24 04 e8 48 04 03 00 0f b6 44 24 ?? 84 c0 74 10 8b 44 24 10 c7 80 ?? ?? ?? ?? 00 00 00 00 eb 04 8b 44 24 10 8b 80 ?? ?? ?? ?? 89 44 24 1c 83 c4}  //weight: 5, accuracy: Low
        $x_1_2 = "atomic.QSY_zrh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCAZ_2147891191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCAZ!MTB"
        threat_id = "2147891191"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 00 32 00 73 00 6f 00 63 00 6b}  //weight: 1, accuracy: High
        $x_1_2 = {63 00 32 00 63 00 6f 00 6e 00 66}  //weight: 1, accuracy: High
        $x_1_3 = {54 00 65 00 73 00 6c 00 61 00 42 00 72 00 6f 00 77 00 73 00 65 00 72}  //weight: 1, accuracy: High
        $x_1_4 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 2e 00 74 00 78 00 74}  //weight: 1, accuracy: High
        $x_1_5 = {53 00 79 00 73 00 6d 00 6f 00 6e 00 44 00 72 00 76}  //weight: 1, accuracy: High
        $x_1_6 = {2a 00 2e 00 65 00 6d 00 6c}  //weight: 1, accuracy: High
        $x_1_7 = "- Screen Resoluton:" ascii //weight: 1
        $x_1_8 = "lid=%s&ver=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_SG_2147892484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.SG!MSR"
        threat_id = "2147892484"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TEXTBIN.NET/raw" ascii //weight: 1
        $x_1_2 = "VMware" ascii //weight: 1
        $x_1_3 = "processhacker" ascii //weight: 1
        $x_1_4 = "ollydbg" ascii //weight: 1
        $x_1_5 = "cuckoo" ascii //weight: 1
        $x_1_6 = "netmon" ascii //weight: 1
        $x_1_7 = "/VERYSILENT /SP-" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCCP_2147893005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCCP!MTB"
        threat_id = "2147893005"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 17 8b 3c 24 6b da ?? 8d bc 3b ?? ?? ?? ?? 89 3c 24 31 d0 89 c2 0f af 14 24 6b d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCCT_2147893361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCCT!MTB"
        threat_id = "2147893361"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 ec 8b 45 0c 30 54 07 ?? 8b 45 ?? 8b 10 8b 45 ?? 31 10 8b 54 9e ?? 8b 45 ?? 03 d1 31 10 3b 7d ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCCV_2147893926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCCV!MTB"
        threat_id = "2147893926"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 3c 32 0f b6 db 31 fb 33 04 9d ?? ?? ?? ?? 46 89 c3 39 f1 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_EM_2147894034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.EM!MTB"
        threat_id = "2147894034"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {2b d8 8b 45 d4 31 18 83 45 ec 04 83 45 d4 04 8b 45 ec 3b 45 d0 72 ba}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCCX_2147894037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCCX!MTB"
        threat_id = "2147894037"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f6 17 33 d8 8b c3 33 f3 33 c0 8b f0 8b c6 33 c6 8b d8 8b f6 80 07 ?? 8b c0 8b f6 8b db 33 d8 8b f0 8b f3 33 de 33 c6 8b f0 80 2f ?? 33 c3 8b f3 33 c6 8b f0 33 c6 33 d8 8b c0 8b f3 33 c6 f6 2f 47 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCCZ_2147894254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCCZ!MTB"
        threat_id = "2147894254"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 f0 8b c3 33 c0 33 db 8b f6 8b db 8b d8 8b c3 f6 2f 47 e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_MA_2147895164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.MA!MTB"
        threat_id = "2147895164"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 dc 8b 00 89 45 d0 83 45 dc 04 8b 45 d4 89 45 d8 8b 45 d8 83 e8 04 89 45 d8 33 c0 89 45 ec 33 c0 89 45 b4 33 c0 89 45 b0 8b 45 e0 8b 10}  //weight: 5, accuracy: High
        $x_5_2 = {2b d8 81 c3 ?? ?? ?? ?? 8b 45 d4 31 18 83 45 ec 04 83 45 d4 04 8b 45 ec 3b 45 d0 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_MB_2147895250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.MB!MTB"
        threat_id = "2147895250"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {89 4c 3c 14 0f b6 44 3e 02 c1 e0 10 09 c8 89 44 3c 14 0f b6 4c 3e 03 c1 e1 18 09 c1 89 4c 3c 14 83 c7 04}  //weight: 5, accuracy: High
        $x_5_2 = {0f b6 3c 02 89 d9 80 e1 18 d3 e7 89 c1 83 e1 fc 31 7c 0c 14 40 83 c3 08 39 c6 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_MC_2147896896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.MC!MTB"
        threat_id = "2147896896"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8d 85 fc eb ff ff 89 4d 10 2b f0 8d 85 f8 eb ff ff 6a 00 50 56 8d 85 fc eb ff ff 50 57 ff 15}  //weight: 5, accuracy: High
        $x_2_2 = ".vuia3" ascii //weight: 2
        $x_2_3 = "_GetPhysicalSize@12" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_MD_2147896897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.MD!MTB"
        threat_id = "2147896897"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {22 eb f5 44 22 74 06 75 04 94 16 31 99 c7 44 24 fc 30 00 00 00 83 ec 04 75}  //weight: 2, accuracy: High
        $x_2_2 = {3d 3f d5 0e 82 43 c3 18 ea 3f c8 01 d2 2a b2 2a 72 03 cd 39 43 4c 36 28 6b b9 af 45 6c f1 cd 3f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ME_2147897140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ME!MTB"
        threat_id = "2147897140"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c1 f6 d1 80 c9 61 00 c8 04 9f 20 c8 f6 d0 a2}  //weight: 1, accuracy: High
        $x_1_2 = {89 c1 83 c1 01 89 0f 0f b6 00 8b 55 ec 8b 0a 8b 75 f0 89 04 8e 8b 07 89 c1 83 c1 01 89 0f 0f b6 00 c1 e0 08 8b 0a 8b 14 8e 89 c6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_MF_2147897141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.MF!MTB"
        threat_id = "2147897141"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 40 04 2d ?? ?? ?? ?? 01 47 68 a1 ?? ?? ?? ?? 8b 48 3c 8b 47 54 83 c1 ?? 03 c1 8b 8f a4 00 00 00 0f af 87 a0 00 00 00 89 87 a0 00 00 00 a1 ?? ?? ?? ?? 88 1c 08 ff 05 ?? ?? ?? ?? 81 fd ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_MG_2147898259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.MG!MTB"
        threat_id = "2147898259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4c 24 34 01 4c 24 14 8b f3 c1 ee 05 8d 3c 2b 83 f8 1b 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCEX_2147898444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCEX!MTB"
        threat_id = "2147898444"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 2c 3e 6a 6a}  //weight: 1, accuracy: High
        $x_1_2 = {80 34 3e 8b 6a}  //weight: 1, accuracy: High
        $x_1_3 = {80 34 3e 85 6a}  //weight: 1, accuracy: High
        $x_1_4 = {80 04 3e b1 6a}  //weight: 1, accuracy: High
        $x_1_5 = {80 34 3e f1 6a}  //weight: 1, accuracy: High
        $x_1_6 = {80 04 3e 4b 6a}  //weight: 1, accuracy: High
        $x_1_7 = {80 04 3e ad 6a}  //weight: 1, accuracy: High
        $x_1_8 = {80 34 3e a8 6a}  //weight: 1, accuracy: High
        $x_1_9 = {80 04 3e f8 6a}  //weight: 1, accuracy: High
        $x_1_10 = {80 04 3e 6f 46 3b 74 24 ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCFE_2147898762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCFE!MTB"
        threat_id = "2147898762"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 24 8b 4c 24 ?? 0f b6 04 08 8b 4c 24 ?? 83 e1 1f 0f b6 4c 0c ?? 31 c8 8b 4c 24 0c 8b 54 24 ?? 88 04 11 8b 44 24 ?? 83 c0 01 89 44 24 08 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_MH_2147898881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.MH!MTB"
        threat_id = "2147898881"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 10 33 c6 89 44 24 10 8b 44 24 18 31 44 24 10 2b 7c 24 10 81 c5 ?? ?? ?? ?? ff 4c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_MI_2147899083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.MI!MTB"
        threat_id = "2147899083"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c6 89 44 24 10 8b 44 24 1c 31 44 24 10 2b 5c 24 10 c7 44 24 ?? ?? ?? ?? ?? 8b 44 24 34 01 44 24 18 2b 7c 24 18 ff 4c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_NL_2147899512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.NL!MTB"
        threat_id = "2147899512"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {76 02 8b e9 33 c0 33 ff 3b eb 74 2e}  //weight: 3, accuracy: High
        $x_3_2 = {e8 36 fa ff ff 83 c4 ?? 80 7e 48 00 75 10 85 c0 78 0c 8b 4c 24 14 88}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_NL_2147899512_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.NL!MTB"
        threat_id = "2147899512"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {7c 16 43 33 f6 8b 47 ?? 8b d6 e8 e3 08 fc ff e8 26 fd fa ff 46 4b 75 ed}  //weight: 5, accuracy: Low
        $x_1_2 = "DiedHistoric" ascii //weight: 1
        $x_1_3 = "Andrews Signed Symposium Cart Nation Euros" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCFS_2147899685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCFS!MTB"
        threat_id = "2147899685"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ce f7 e6 c1 ea ?? 6b c2 ?? 2b c8 8a 81 ?? ?? ?? ?? 30 86 ?? ?? ?? ?? 46 3b f7 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_MJ_2147899799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.MJ!MTB"
        threat_id = "2147899799"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4c 24 14 8b 44 24 10 c1 e9 05 03 4c 24 30 81 3d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCFX_2147899807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCFX!MTB"
        threat_id = "2147899807"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 fe 0f be 44 14 ?? 31 c1 0f be c1 8b 4c 24 ?? 8b 54 24 ?? 66 89 04 51 eb}  //weight: 1, accuracy: Low
        $x_1_2 = "LummaC2" ascii //weight: 1
        $x_1_3 = "lummanowork" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCFZ_2147900035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCFZ!MTB"
        threat_id = "2147900035"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f4 83 e9 01 89 4d f4 8b 55 fc 33 55 f4 89 95 ?? ?? ?? ?? 8b 45 f4 83 e8 01 89 45 f4 83 bd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RPY_2147900691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPY!MTB"
        threat_id = "2147900691"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d b4 8b f0 6a 00 8d 45 a0 c7 45 a0 00 00 00 00 50 8b 11 6a 01 51 ff 52 0c 85 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RPY_2147900691_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPY!MTB"
        threat_id = "2147900691"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 46 78 89 c4 50 83 ec 1c 89 e0 83 e0 f0 89 46 70 89 c4 50 83 ec 0c 89 e0 83 e0 f0 89 46 7c 89 c4 50 83 ec 1c 89 e0 83 e0 f0 89 86 80 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCGW_2147900941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCGW!MTB"
        threat_id = "2147900941"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 d1 41 ff e1 31 c9 3d ?? ?? ?? ?? 0f 9c c1 8b 0c 8d ?? ?? ?? ?? ba ?? ?? ?? ?? 33 15 ?? ?? ?? ?? 01 d1 41 ff e1 31 c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCHB_2147901239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCHB!MTB"
        threat_id = "2147901239"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 53 57 56 83 ec ?? 8b 4c 24 ?? a1 ?? ?? ?? ?? ba ?? ?? ?? ?? 33 15 ?? ?? ?? ?? 01 d0 40 66 90 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCHC_2147901336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCHC!MTB"
        threat_id = "2147901336"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 04 68 00 30 00 00 50 6a 00 53 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {50 ff 75 f8 ff 75 b0 57 53 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_MK_2147901715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.MK!MTB"
        threat_id = "2147901715"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 f0 8b f3 f6 2f 47 e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCHF_2147901759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCHF!MTB"
        threat_id = "2147901759"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 8b c6 f7 f1 8b 45 ?? 46 8a 0c 02 8b 55 ?? 32 0c 3a 88 0f 8b 7d ?? 3b f3 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ML_2147902060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ML!MTB"
        threat_id = "2147902060"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 75 f0 c7 45 [0-5] 83 45 f4 03 8b 45 ec c1 e0 04 83 3d [0-4] 0c 89 45 fc 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_A_2147902077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.A!MTB"
        threat_id = "2147902077"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {80 07 25 80 2f ?? 8b ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f6 2f 47 e2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_NLA_2147902335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.NLA!MTB"
        threat_id = "2147902335"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {75 d5 f6 c2 01 8b 7c 24 ?? 74 20 89 c2 81 f2 fe ff ff 3f}  //weight: 3, accuracy: Low
        $x_3_2 = {c9 89 8c 84 ?? ?? ?? ?? 83 bc 24 c8 15 00 00 ?? 0f 8e c0 00 00 00 31 c0 8b 4c 24 ?? 8d 0c c9 89 ca}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_NSE_2147902408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.NSE!MTB"
        threat_id = "2147902408"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {6b d2 28 8b 85 5c ff ff ff 8b 4c 10 ?? 89 8d e4 fe ff ff 8b 95 ?? ?? ?? ?? 81 e2 00 00 00 40 74 27}  //weight: 3, accuracy: Low
        $x_3_2 = {eb 0f 8b 95 ?? ?? ?? ?? 83 c2 01 89 95 ?? ?? ?? ?? 8b 85 68 ff ff ff 0f b7 48 06}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_PADL_2147902484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.PADL!MTB"
        threat_id = "2147902484"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {51 c7 04 24 f0 43 03 00 83 04 24 0d a1 78 07 47 00 0f af 04 24 05 c3 9e 26 00 a3 78 07 47 00 0f b7 05 7a 07 47 00 25 ff 7f 00 00 59 c3}  //weight: 1, accuracy: High
        $x_1_2 = {30 04 1e 46 3b f7 7c e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_NLE_2147902617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.NLE!MTB"
        threat_id = "2147902617"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Guardrails Aloin Cogent" ascii //weight: 2
        $x_2_2 = "Signor Shereefs Mossgrown" ascii //weight: 2
        $x_2_3 = "List Controller Setup" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_B_2147902821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.B!MTB"
        threat_id = "2147902821"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 c0 8b 04 85 ?? ?? ?? ?? b9 ?? ?? ?? ?? 33 0d ?? ?? ?? ?? 01 c8 40}  //weight: 2, accuracy: Low
        $x_1_2 = "Windows 10" ascii //weight: 1
        $x_1_3 = "Windows 11" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCHX_2147905293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCHX!MTB"
        threat_id = "2147905293"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 04 31 83 ff 0f 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_SPD_2147905681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.SPD!MTB"
        threat_id = "2147905681"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 45 ec 31 45 e8 8b 45 f4 33 45 e8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_MAC_2147906485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.MAC!MTB"
        threat_id = "2147906485"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a1 bc 50 44 00 69 c0 fd 43 03 00 05 c3 9e 26 00 a3 bc 50 44 00 8a 0d be 50 44 00 30 0c 33 83 ff 0f 75 39}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_NM_2147907640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.NM!MTB"
        threat_id = "2147907640"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 35 08 91 75 00 8d 4f ?? 03 74 24 18 ba ?? ?? ?? ?? 8b 5e 04 2b f7}  //weight: 3, accuracy: Low
        $x_3_2 = {8b 04 0e 8d 49 ?? 03 c3 89 41 fc 83 ea 01 75 f0 a1 0c 91 75 00 89 47 08 8d 44 24 10}  //weight: 3, accuracy: Low
        $x_1_3 = "GameJack" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_JHU_2147907724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.JHU!MTB"
        threat_id = "2147907724"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 08 8b 4c 24 10 8b 54 24 14 88 44 3c 18 88 5c 2c ?? 0f b6 44 3c ?? 03 c6 0f b6 c0 0f b6 44 04 ?? 30 04 0a 41 89 4c 24 10 3b 8c 24 24 02 00 00 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_TTB_2147907887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.TTB!MTB"
        threat_id = "2147907887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ff 8b 15 ?? ?? ?? ?? 8b 44 24 0c 69 d2 fd 43 03 00 81 c2 c3 9e 26 00 89 15 14 ea 44 00 8a 0d ?? ?? 44 00 30 0c 30 83 ff 0f 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_NME_2147908252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.NME!MTB"
        threat_id = "2147908252"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {32 37 3e 34 ?? 83 c4 04 5b 69 8d ?? ?? ?? ?? fe 00 00 00 81 c1 3b 66 f3 56 69 95 ?? ?? ?? ?? fe 00 00 00}  //weight: 3, accuracy: Low
        $x_3_2 = {49 4c 39 4f ?? 3e 4c 39 37 45 83 c4 ?? 5b 8b 8d 84 fd ff ff}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RO_2147909020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RO!MTB"
        threat_id = "2147909020"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 14 24 c7 44 24 04 00 00 00 00 c7 44 24 08 00 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 14 04 00 00 00 c7 44 24 18 00 00 00 00 c7 44 24 1c 00 00 00 00 89 4c 24 20 89 44 24 24 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {89 14 24 89 4c 24 04 89 44 24 08 c7 44 24 0c 00 30 00 00 c7 44 24 10 40 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_C_2147909823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.C!MTB"
        threat_id = "2147909823"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {21 c8 01 c0 89 c1 31 d1 f7 d0 21 d0 01 c0 29 c8 89 c1 83 c9 ?? 83 e0 ?? 01 c8 fe c0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCIF_2147909879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCIF!MTB"
        threat_id = "2147909879"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {21 c8 01 c0 89 c1 31 d1 f7 d0 21 d0 01 c0 29 c8 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCIG_2147912936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCIG!MTB"
        threat_id = "2147912936"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ec 28 8b 6c 24 ?? a1 ?? ?? ?? ?? b9 ?? ?? ?? ?? 33 0d ?? ?? ?? ?? 01 c8 40 90 90 ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCIH_2147912937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCIH!MTB"
        threat_id = "2147912937"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 95 c2 8b 04 95 ?? ?? ?? ?? ba ?? ?? ?? ?? 33 15 ?? ?? ?? ?? 01 c2 42 31 c0 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_MVV_2147912963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.MVV!MTB"
        threat_id = "2147912963"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 0c 8b 4c 24 18 03 c6 0f b6 c0 8a 44 04 ?? 30 04 29 45 3b ac 24 28 02 00 00 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_MWW_2147912992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.MWW!MTB"
        threat_id = "2147912992"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 d9 80 e1 10 d3 e5 89 fa 83 e2 fc 33 6c 14 1c 89 6c 14 ?? 0f b6 74 38 01 80 c9 08 d3 e6 31 ee 89 74 14 ?? 83 c7 02 83 c3 10 39 3c 24 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_MML_2147913229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.MML!MTB"
        threat_id = "2147913229"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {54 03 c3 2e 82 a7 a7 a7 a7 4c 96 8d 05 02 20 40 00 80 30 a7 40 3d 34 20 40 00 75 ?? 05 54 82 37 1c 29 c0 29 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_YR_2147913412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.YR!MTB"
        threat_id = "2147913412"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {29 c0 29 c0 0f c8 8d 05 00 20 40 00 83 c0 02 50 11 c0 8d 80 42 44 23 0b 58 ff e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCIQ_2147913508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCIQ!MTB"
        threat_id = "2147913508"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 07 cb 65 fa 63 c7 47 ?? e5 61 f0 6f c7 47 ?? f2 6d b1 6b c7 47 ?? b4 69 ba 57 c7 47 ?? fa 55 c0 53 c7 47 ?? c6 51 50 5f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RON_2147913979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RON!MTB"
        threat_id = "2147913979"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 89 b5 f8 fb ff ff e8 ?? ?? ?? ?? 8a 85 f8 fb ff ff 30 04 3b 83 7d 08 0f 59 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RRC_2147914137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RRC!MTB"
        threat_id = "2147914137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 24 8b 4c 24 3c 8b 74 24 30 03 0a 0f b6 06 30 01 8b c2 8b 4c 24 ?? 2b ca 83 e1 fc 81 f9 00 10 00 00 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCIY_2147914469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCIY!MTB"
        threat_id = "2147914469"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 02 8b 8d ?? f8 ff ff 8b 11 83 c2 01 33 c2 8b 8d ?? f8 ff ff c1 e1 00 03 8d ?? f8 ff ff 88 01 eb ?? 8b 95 ?? f8 ff ff 8b 02 83 c0 02 8b 8d ?? f8 ff ff 39 01 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCIZ_2147915033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCIZ!MTB"
        threat_id = "2147915033"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 57 56 83 e4 ?? 83 ec ?? 89 e6 a1 ?? ?? ?? ?? b9 ?? ?? ?? ?? 33 0d ?? ?? ?? ?? 01 c8 40 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_GZX_2147915673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.GZX!MTB"
        threat_id = "2147915673"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {89 d1 c1 e9 06 80 c1 c0 88 4d 00 80 e2 3f 80 ca 80 88 55 01}  //weight: 5, accuracy: High
        $x_5_2 = {83 cb 0a 0f af 5c 24 0c 83 74 24 0c 0a 8b 7c 24 04 83 e7 f5 0f af 7c 24 0c 89 7c 24 04}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCJB_2147915675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCJB!MTB"
        threat_id = "2147915675"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 54 14 10 81 c1 ?? ?? ?? ?? 31 d1 89 4c 24 08 8b 4c 24 08 89 ca 83 ca 45 83 e1 45 01 d1 fe c1 8b 54 24 04 88 4c 14 10 ff 44 24 04 8b 4c 24 04 83 f9 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_BBA_2147915703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.BBA!MTB"
        threat_id = "2147915703"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {34 ac 2c 65 34 22 2c 73 68 ?? ?? ?? ?? 88 04 37 e8 22 6d fe ff 30 04 37 83 c4 1c 46 3b 75 18 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_PH_2147915993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.PH!MTB"
        threat_id = "2147915993"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {59 8b 14 98 8b 44 24 ?? 8b 48 08 8b 44 24 ?? 8a 04 01 8d 4c 24 ?? 30 82}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_QTW_2147916525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.QTW!MTB"
        threat_id = "2147916525"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 14 b0 8b 44 24 24 81 c2 ?? ?? ?? ?? 8b 4c b0 04 8b 44 24 3c 8a 04 01 8d 4c 24 24 30 02 e8 ?? ?? ?? ?? 8d 4c 24 48 e8 ?? ?? ?? ?? 8d 4c 24 30 e8 ?? ?? ?? ?? 8d 4c 24 3c e8 ?? ?? ?? ?? 8b 44 24 18 47 89 7c 24 14 81 ff 00 2c 12 00 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_AMAX_2147917143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.AMAX!MTB"
        threat_id = "2147917143"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0c b8 8b 44 24 ?? 8a 04 01 8d 4c 24 ?? 30 [0-5] e8 ?? ?? ?? ?? 8d 4c 24 ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_AFZ_2147917295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.AFZ!MTB"
        threat_id = "2147917295"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 01 30 04 37 8b 44 24 18 2b c1 83 e0 fc 50 51 e8 ?? ?? ?? ?? 46 89 5c 24 18 59 59 89 5c 24 14 89 5c 24 18 3b 74 24 30 0f 82}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_DA_2147917488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.DA!MTB"
        threat_id = "2147917488"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = "<HTA:APPLICATION icon=\"#\" WINDOWSTATE=\"normal\" SHOWINTASKBAR=\"no\" SYSMENU=\"no\" CAPTION=\"no\" BORDER=\"none\" SCROLL=\"no\"" ascii //weight: 20
        $x_20_2 = "<HTA:APPLICATION CAPTION = \"no\" WINDOWSTATE = \"minimize\" SHOWINTASKBAR = \"no\"" ascii //weight: 20
        $x_1_3 = "window.close();" ascii //weight: 1
        $x_1_4 = {65 00 76 00 61 00 6c 00 28 00 [0-15] 29 00}  //weight: 1, accuracy: Low
        $x_1_5 = {65 76 61 6c 28 [0-15] 29}  //weight: 1, accuracy: Low
        $x_1_6 = "</script>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 3 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_LummaStealer_AMAC_2147918784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.AMAC!MTB"
        threat_id = "2147918784"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 fe 81 ef [0-4] 2b f8 31 3b 83 45 ec 04 6a 00 e8 ?? ?? ?? ?? 83 c0 04 01 c3 8b 45 ec 3b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_AMAE_2147919161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.AMAE!MTB"
        threat_id = "2147919161"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b f8 31 3b 83 45 ec 04 6a 00 e8 ?? ?? ?? ?? 83 c0 04 01 c3 8b 45 ?? 3b 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_MNZ_2147919283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.MNZ!MTB"
        threat_id = "2147919283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {89 da 83 e2 1e 0f b6 54 14 0c 32 54 1d 20 88 54 1d 00 8d 53 01 83 e2 1f 0f b6 54 14 0c 32 54 1d 21 88 54 1d 01 83 c3 02 39 d9 75 d4}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_MFF_2147919627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.MFF!MTB"
        threat_id = "2147919627"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {ba 48 00 00 00 29 c2 05 b7 25 94 b0 31 c2 21 ca 31 c2 89 54 24 04 8b 44 24 04 fe c8 8b 0c 24 88 44 0c 08 ff 04 24 8b 04 24 83 f8 20 72 c7}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_TRI_2147920357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.TRI!MTB"
        threat_id = "2147920357"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {29 c2 05 3a ac 7c c9 31 c2 21 ca 31 c2 89 54 24 0c 8b 44 24 0c 04 6a 8b 4c 24 04 88 44 0c 38 ff 44 24 04 8b 44 24 04 83 f8 2d 72 c2}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_GPH_2147920500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.GPH!MTB"
        threat_id = "2147920500"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 0c 0f 05 ?? ?? ?? ?? 31 c8 89 45 ?? 8b 45 ?? 04 ?? 8b 4d ?? 88 04 0f ff 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_XCA_2147920797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.XCA!MTB"
        threat_id = "2147920797"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {31 d1 89 4d e4 8b 4d e4 80 c1 36 8b 55 ?? 88 0c 10 ff 45 ec 8b 4d ec 83 f9 16 72}  //weight: 4, accuracy: Low
        $x_5_2 = {31 fe 89 75 e8 8b 5d e8 80 c3 d6 8b 75 ?? 88 1c 30 ff 45 f0 8b 75 f0 83 fe 06 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RP_2147921207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RP!MTB"
        threat_id = "2147921207"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.UlhMFyDdoz" ascii //weight: 1
        $x_1_2 = "main.AEKCihaLRV" ascii //weight: 1
        $x_10_3 = "main.uydiOYgQCH.deferwrap2" ascii //weight: 10
        $x_10_4 = "main.uydiOYgQCH.deferwrap1" ascii //weight: 10
        $x_10_5 = "main.mOaSjsgDny.func1.Print.1" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

