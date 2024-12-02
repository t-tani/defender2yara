rule Trojan_Win64_Mikey_SIB_2147807424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.SIB!MTB"
        threat_id = "2147807424"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "ServiceMain" ascii //weight: 10
        $x_10_2 = "svchost.exe" wide //weight: 10
        $x_10_3 = "rundll32.exe" wide //weight: 10
        $x_1_4 = {45 33 c9 43 8a 3c 11 49 ff c1 4d 3b c8 7d ?? 43 8a 34 11 49 ff c1 eb ?? 41 bc ?? ?? ?? ?? 4d 3b c8 7d ?? 43 8a 2c 11 49 ff c1 eb ?? bb ?? ?? ?? ?? 44 8a f7 40 80 e7 ?? 40 8a c6 c0 e8 ?? 40 c0 e7 ?? 40 8a ce 40 0a f8 80 e1 ?? 40 8a c5 c0 e8 ?? c0 e1 ?? 41 c0 ee ?? 0a c8 40 8a c5 24 ?? 45 85 e4 74 ?? b1 ?? eb ?? 0f b6 d0 85 db b8 ?? ?? ?? ?? 0f 45 d0 41 0f b6 c6 4c 8d 35 ?? ?? ?? ?? 0f b6 c9 42 8a 04 30 41 83 c3 04 41 88 45 ?? 40 0f b6 c7 49 83 c5 ?? 42 8a 04 30 41 88 45 ?? 42 8a 0c 31 41 88 4d ?? 0f b6 ca ba ?? ?? ?? ?? 42 8a 0c 31 41 88 4d ?? 4d 3b c8 0f 8c}  //weight: 1, accuracy: Low
        $x_1_5 = {48 8b f2 4c 8b f9 4d 63 f0 48 8d 2d ?? ?? ?? ?? 44 8b ef 43 0f b6 54 3d ?? 48 8b cd ff 15 ?? ?? ?? ?? 43 0f b6 54 3d ?? 48 8b cd 48 8b d8 40 2a dd ff 15 ?? ?? ?? ?? 43 0f b6 54 3d ?? 4c 8b e0 48 8b cd 44 2a e5 ff 15 ?? ?? ?? ?? 43 0f b6 54 3d ?? 48 8b e8 48 8d 05 ?? ?? ?? ?? 48 8b c8 40 2a e8 ff 15 ?? ?? ?? ?? c0 e3 ?? 40 8a cd 4c 8b d8 48 8d 05 ?? ?? ?? ?? c0 e1 06 44 2a d8 41 8a c4 49 83 c5 ?? c0 e8 ?? 41 0a cb ff c7 0a c3 88 06 48 ff c6 40 80 fd ?? 74 ?? 40 c0 ed ?? 41 c0 e4 ?? ff c7 41 0a ec 40 88 2e 48 ff c6 41 80 fb ?? 74 ?? 88 0e ff c7 48 ff c6 48 8d 2d ?? ?? ?? ?? 4d 3b ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Mikey_AMBC_2147898723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.AMBC!MTB"
        threat_id = "2147898723"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {49 39 c7 74 ?? 8a 4c 05 d0 41 30 4c 05 00 48 ff c0 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_AMCD_2147898994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.AMCD!MTB"
        threat_id = "2147898994"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8d 0c 30 41 ff c0 80 34 39 ?? 44 3b c0 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_CCFM_2147899647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.CCFM!MTB"
        threat_id = "2147899647"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {21 c9 89 8c 24 ?? ?? ?? ?? 4c 89 5c 24 50 66 8b 44 24 1e 66 83 f0 ff 66 89 84 24 ?? ?? ?? ?? 4c 89 b4 24 ?? ?? ?? ?? 8b 4c 24 20 69 c9 ?? ?? ?? ?? 89 8c 24 ?? ?? ?? ?? 4d 39 c3 0f 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_HNS_2147905331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.HNS!MTB"
        threat_id = "2147905331"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {4e 00 61 00 6d 00 65 00 00 00 00 00 4c 00 61 00 75 00 6e 00 63 00 68 00 65 00 72 00 00 00 00 00 3a 00 09 00 01 00 46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 4c 00 61 00 75 00 6e 00 63 00 68 00 65 00 72 00}  //weight: 2, accuracy: High
        $x_2_2 = "C:\\Users\\mpx16\\source\\repos\\Launcher\\bin\\Release\\net8.0\\win-x64\\native\\Launcher.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_AMI_2147907010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.AMI!MTB"
        threat_id = "2147907010"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b df eb 38 48 8d 15 f3 a5 00 00 48 8b cb ff 15 9a 1e 00 00 48 85 c0 74 e6 48 8d 15 f6 a5 00 00 48 89 05 27 fb 00 00 48 8b cb ff 15 7e 1e 00 00 48 85 c0 74 ca}  //weight: 2, accuracy: High
        $x_2_2 = {ff 48 85 d2 7e 24 49 2b f6 4b 8b 8c eb 50 69 02 00 49 03 ce 42 8a 04 36 42 88 44 f9 3e ff c7 49 ff c6 48 63 c7 48 3b c2}  //weight: 2, accuracy: High
        $x_1_3 = "node_modules\\windo32lib\\build\\Release\\windo32lib.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_AMY_2147907962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.AMY!MTB"
        threat_id = "2147907962"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 8b 4d df 89 45 d7 4d 85 c9 4c 89 75 ff 48 8d 45 e7 89 75 f7 48 89 44 24 30 4c 8d 45 d7 4d 0f 44 c7 44 89 7c 24 28 45 33 c9 4c 89 7c 24 20 33 d2 48 8d 4d f7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_CCHW_2147909905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.CCHW!MTB"
        threat_id = "2147909905"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {4c 0f 44 c5 89 6c 24 28 45 33 c9 48 89 6c 24 20 33 d2 48 8d 4c 24 60 ff 15}  //weight: 5, accuracy: High
        $x_5_2 = {8b 54 24 40 4c 8b cf 44 8b c6 48 8b cb ff 15}  //weight: 5, accuracy: High
        $x_1_3 = "modules\\win32crypted\\src\\win32decrypt" ascii //weight: 1
        $x_1_4 = "modules\\windo32lib\\src\\windo32lib" ascii //weight: 1
        $x_1_5 = "modules\\maximumpswd\\src\\maximumpswd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Mikey_NB_2147915263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.NB!MTB"
        threat_id = "2147915263"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {83 7d 00 00 0f 95 c0 88 07 b0 01 48 8b 4d 08 48 33 cd e8}  //weight: 10, accuracy: High
        $x_1_2 = "C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\powershell" ascii //weight: 1
        $x_1_3 = "$BlockedFromReflection" ascii //weight: 1
        $x_1_4 = "$disable regedit" ascii //weight: 1
        $x_1_5 = "$disable uac" ascii //weight: 1
        $x_1_6 = "$start with windows" ascii //weight: 1
        $x_1_7 = "hentai" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_GMN_2147921671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.GMN!MTB"
        threat_id = "2147921671"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0a 59 b8 a4 42 30 f3 8a cb 5e 85 0a 24 a2 1a ef b7 20}  //weight: 5, accuracy: High
        $x_5_2 = {f6 03 1d 8f 41 5b 5a 91 33 50 10}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_GMT_2147921673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.GMT!MTB"
        threat_id = "2147921673"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {21 4e 95 8c 62 45 03 87 ?? ?? ?? ?? 32 fd 2d}  //weight: 5, accuracy: Low
        $x_5_2 = {8e 04 73 19 a4 74 ?? ?? ?? ?? d0 31 2e e7 6d e2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_MKV_2147921732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.MKV!MTB"
        threat_id = "2147921732"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {41 89 f1 4c 6b d2 50 4c 01 d0 48 83 c0 40 44 33 18 44 89 de 89 f0 4c 03 8c 24 b0 00 00 00 89 4c 24 44 4c 89 c9 48 89 54 24 38 4c 89 c2 49 89 c0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_ASJ_2147922823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.ASJ!MTB"
        threat_id = "2147922823"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {48 8b c8 ff 15 ?? ?? ?? ?? 45 33 c9 4c 89 64 24 28 4c 8d 05 ?? ?? ?? ?? 44 89 64 24 20 33 d2 33 c9 ff 15 ?? ?? ?? ?? 48 85 c0 75 1d 48 8d ?? ?? ?? ?? 00 4c 8b a4 24 a8 00 00 00 48 83 c4 70 41 5f 41 5e 5d e9 ?? ?? ?? ?? ba ff ff ff ff 48 8b c8 ff 15}  //weight: 4, accuracy: Low
        $x_1_2 = "ServiceMain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_NE_2147923487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.NE!MTB"
        threat_id = "2147923487"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "start cmd /C \"COLOR C && echo. Outdated version, contact fael#2081 && TIMEOUT 10 > nul" ascii //weight: 2
        $x_1_2 = "xxxx?xxxx????xxx" ascii //weight: 1
        $x_1_3 = "----------------%ld%s" ascii //weight: 1
        $x_1_4 = "security.dll" ascii //weight: 1
        $x_1_5 = "DecryptMessage" ascii //weight: 1
        $x_1_6 = "C:\\Windows\\KsDumperDriver.sys" ascii //weight: 1
        $x_1_7 = "AppData\\Local\\dnSpy" ascii //weight: 1
        $x_1_8 = "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs" ascii //weight: 1
        $x_1_9 = "\\examples\\Exe\\" ascii //weight: 1
        $x_1_10 = "netsh advfirewall firewall add rule name" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_GZT_2147925149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.GZT!MTB"
        threat_id = "2147925149"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {5b 59 8b d1 32 fd 24}  //weight: 5, accuracy: High
        $x_5_2 = {14 1c 34 39 10 b0 ?? ?? ?? ?? 31 74 9a ?? 59 ?? ?? ?? ?? 54 5e f6 ed}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mikey_GTZ_2147925895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.GTZ!MTB"
        threat_id = "2147925895"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {f3 8b ec 60 97 30 68 ?? 63 fb 1c 61 0c ce 00 e1 e2 ?? 6a 85 30 00}  //weight: 10, accuracy: Low
        $x_10_2 = {30 24 73 1c f6 2b 31 03 f1 31 1f 09 d7 92 ?? fe 64 bc ?? ?? ?? ?? 21 cb 20 e2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Mikey_GTK_2147927354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mikey.GTK!MTB"
        threat_id = "2147927354"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {d3 e2 30 9e ?? ?? ?? ?? a3 ?? ?? ?? ?? ?? ?? ?? ?? d2 d0 54 a3 ?? ?? ?? ?? ?? ?? ?? ?? 6a d0 54 a3}  //weight: 5, accuracy: Low
        $x_5_2 = {f7 d1 c1 c9 ?? 44 31 4c 54 ?? 41 ff c9 ff c9 f7 d9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

