rule Trojan_Win32_Blackmoon_CA_2147805528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Blackmoon.CA!MTB"
        threat_id = "2147805528"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Blackmoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 7c 24 2c 83 c9 ff 33 c0 f2 ae f7 d1 49 03 ce 42 83 fa 04 8a 4c 11 ff 88 4c 14 17 7c e2}  //weight: 1, accuracy: High
        $x_1_2 = "WoWEmuHacker" ascii //weight: 1
        $x_1_3 = "Wow.exe" ascii //weight: 1
        $x_1_4 = "www.dywt.com.cn" ascii //weight: 1
        $x_1_5 = "http://www.eyuyan.com" ascii //weight: 1
        $x_1_6 = "service@dywt.com.cn" ascii //weight: 1
        $x_1_7 = "GetTickCount" ascii //weight: 1
        $x_1_8 = "QueryPerformanceCounter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Blackmoon_AP_2147829921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Blackmoon.AP!MTB"
        threat_id = "2147829921"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Blackmoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dybldat.dll" ascii //weight: 1
        $x_1_2 = "www.52kkg.com/so.php" ascii //weight: 1
        $x_1_3 = "jd.kx778.com/plus/search.php" ascii //weight: 1
        $x_1_4 = "www.qiken.cn" ascii //weight: 1
        $x_1_5 = "{6AEDBD6D-3FB5-418A-83A6-7F45229DC872}" ascii //weight: 1
        $x_1_6 = "www.taobao.com/webww/ww.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Blackmoon_ARA_2147837909_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Blackmoon.ARA!MTB"
        threat_id = "2147837909"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Blackmoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "cmd /c schtasks /delete /tn * /f" ascii //weight: 2
        $x_2_2 = "trapceapet.exe" ascii //weight: 2
        $x_2_3 = "BlackMoon RunTime Error:" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Blackmoon_ARA_2147837909_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Blackmoon.ARA!MTB"
        threat_id = "2147837909"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Blackmoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 39 c1 ef 02 c1 e2 06 8d 54 17 01 8b f8 41 2b fa 8b da c1 ee 05 4e 8a 17 88 10 8a 57 01 88 50 01 83 c0 02 83 c7 02 8a 17 88 10 40 47 4e 75 f7}  //weight: 2, accuracy: High
        $x_1_2 = "coderpub" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Blackmoon_RPQ_2147850591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Blackmoon.RPQ!MTB"
        threat_id = "2147850591"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Blackmoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 39 c1 ef 02 c1 e2 06 8d 54 17 01 8b f8 41 2b fa 8b da c1 ee 05 4e 8a 17 88 10 8a 57 01 88 50 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Blackmoon_RPY_2147903446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Blackmoon.RPY!MTB"
        threat_id = "2147903446"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Blackmoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 54 17 01 8b f8 41 2b fa 8b da c1 ee 05 4e 8a 17 88 10 8a 57 01 88 50 01 83 c0 02 83 c7 02 8a 17 88 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Blackmoon_NB_2147913575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Blackmoon.NB!MTB"
        threat_id = "2147913575"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Blackmoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "47.99.214.214" ascii //weight: 2
        $x_2_2 = "otalm.txt" ascii //weight: 2
        $x_2_3 = "BlackMoon RunTime Error" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Blackmoon_MBXH_2147916277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Blackmoon.MBXH!MTB"
        threat_id = "2147916277"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Blackmoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 30 34 38 35 37 36 38 39 31 [0-89] 80 56 40 00 00 00 00 00 00 4d 40 01 00 00 00 00 00 00 00 64 73 31 35 5f 36 65 31 76 35 65 77 39 5f 37 34 79}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Blackmoon_NC_2147917179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Blackmoon.NC!MTB"
        threat_id = "2147917179"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Blackmoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8d 86 80 04 00 00 3b f0 73 ?? 80 66 04 00 83 0e ff 83 66 08 00 c6 46 05 0a a1 80 3c 45 00 83 c6 24 05 80 04 00 00}  //weight: 3, accuracy: Low
        $x_1_2 = "/*rep1021lace*/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Blackmoon_PPDW_2147921787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Blackmoon.PPDW!MTB"
        threat_id = "2147921787"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Blackmoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd /c echo Y|schtasks /create /sc minute /mo " ascii //weight: 1
        $x_2_2 = "YgtpXIhOOjrgrnEw.exe" ascii //weight: 2
        $x_1_3 = "BMpZwFgLiInafedu.exe" ascii //weight: 1
        $x_1_4 = "dVaaODoAqUaeWdcG.exe" ascii //weight: 1
        $x_1_5 = "jqMfBieXoEUDXAzZ.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

