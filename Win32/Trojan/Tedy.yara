rule Trojan_Win32_Tedy_MA_2147834060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tedy.MA!MTB"
        threat_id = "2147834060"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 f0 83 c0 01 89 45 f0 83 7d f0 03 7d 1a 8b 4d c4 03 4d e0 8b 55 f0 8a 44 15 e4 88 01 8b 4d e0 83 c1 01 89 4d e0 eb}  //weight: 10, accuracy: High
        $x_5_2 = "desktop.d" ascii //weight: 5
        $x_5_3 = "DllRegisterServer" ascii //weight: 5
        $x_2_4 = "exculpatorily" ascii //weight: 2
        $x_2_5 = "hemophagy" ascii //weight: 2
        $x_2_6 = "hygiologist" ascii //weight: 2
        $x_2_7 = "oncometric" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tedy_EM_2147847991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tedy.EM!MTB"
        threat_id = "2147847991"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Users\\SirLennox" ascii //weight: 1
        $x_1_2 = "Release\\NekoInstaller.pdb" ascii //weight: 1
        $x_1_3 = "\\ServiceHost.exe" wide //weight: 1
        $x_1_4 = "nekoservice" wide //weight: 1
        $x_1_5 = "CreateDirectoryW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tedy_GMK_2147891590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tedy.GMK!MTB"
        threat_id = "2147891590"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TSAide.stat" ascii //weight: 1
        $x_1_2 = "ver.ourwg.com.tw" ascii //weight: 1
        $x_1_3 = "hrBKUEAH29471C" ascii //weight: 1
        $x_1_4 = "RSA encrypt error :%d" ascii //weight: 1
        $x_1_5 = "hrjiyjj7" ascii //weight: 1
        $x_1_6 = "@.vmp0" ascii //weight: 1
        $x_1_7 = "ZodiacAide.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tedy_MBJV_2147893180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tedy.MBJV!MTB"
        threat_id = "2147893180"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 c4 33 c9 85 c0 0f 95 c1 f7 d9 66 85 c9 74 2f 8d 45 c8 8d 4d d8 8d 55 ec 50 51}  //weight: 1, accuracy: High
        $x_1_2 = {80 08 4a 00 e0 23 40 00 5f f8 b0 00 00 ff ff ff 08 00 00 00 01 00 00 00 02 00 04 00 e9 00 00 00 58 21 40 00 c4 2f 40 00 f0 1f 40 00 78 00 00 00 87 00 00 00 96 00 00 00 97}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tedy_GPC_2147893868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tedy.GPC!MTB"
        threat_id = "2147893868"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "cungu.oss-cn-beijing.aliyuncs.com/payload.bin" wide //weight: 2
        $x_2_2 = "DownloadShellcode" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tedy_GK_2147894383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tedy.GK!MTB"
        threat_id = "2147894383"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Users\\Public\\2.exe" ascii //weight: 1
        $x_1_2 = "C:\\Users\\wegame.exe" ascii //weight: 1
        $x_1_3 = "http://164.155.255.81/2.exe" ascii //weight: 1
        $x_1_4 = "C:\\Users\\Public\\libcef.dll" ascii //weight: 1
        $x_1_5 = "http://164.155.255.81/libcef.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tedy_NBL_2147897303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tedy.NBL!MTB"
        threat_id = "2147897303"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 40 44 52 4c 00 00 8b 4a 6c 03 4a 5c a1 ?? ?? ?? ?? 81 f1 b8 14 0d 00 89 48 54 8b 8a e0 00 00 00 2b 8a 34 01 00 00 a1 ?? ?? ?? ?? 81 f1 f1 0e 1e 00 81 f6 a3 46 00 00 89 88 2c 01 00 00 8b c6 5e 5b c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 8e 08 01 00 00 b8 c0 77 00 00 33 8e ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 2b c1 01 42 28 81 f7 8c 0f 00 00 8b c7 c7 86 08 01 00 00 ?? ?? ?? ?? 5f 5e 5d 5b c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tedy_GPA_2147899065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tedy.GPA!MTB"
        threat_id = "2147899065"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0f 1f 00 8a 88 ?? ?? ?? ?? 80 f1 ?? 88 8c 05 ?? ?? ff ff 40 3d}  //weight: 3, accuracy: Low
        $x_3_2 = "CreateToolhelp32Snapshot" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tedy_SPGQ_2147900207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tedy.SPGQ!MTB"
        threat_id = "2147900207"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "664FirsxxdfdtName" ascii //weight: 1
        $x_1_2 = "cdefcdefcdefcdefcdefhttp://bd.tlysj.com:7979/20.jpg" ascii //weight: 1
        $x_1_3 = "abcdabcdabcdabcdabcdhttp://803.asx51.info:8080/20.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tedy_AMME_2147906180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tedy.AMME!MTB"
        threat_id = "2147906180"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "WYScYYrYiYpYt.YSYhYYelYYYl" wide //weight: 2
        $x_1_2 = "ent).Downlo'; $c3='adString(''" wide //weight: 1
        $x_1_3 = "cmd /c cscript.exe /E:VBScript.Encode Msg.log" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tedy_YAA_2147910535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tedy.YAA!MTB"
        threat_id = "2147910535"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 a8 2b d0 8b 45 ?? 31 10 83 45 ec 04 83 45 d4 04 8b 45 ec 3b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tedy_RV_2147912492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tedy.RV!MTB"
        threat_id = "2147912492"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {69 8d 94 ef ff ff fe 00 00 00 81 c1 3b 66 f3 56 69 95 94 ef ff ff fe 00 00 00 2b ca 33 8d ac e1 ff ff 0f af 8d 94 ef ff ff 69 85 94 ef ff ff fe 00 00 00 2b c8 89 8d 90 ef ff ff}  //weight: 5, accuracy: High
        $x_1_2 = "\\output\\G2M_Dll.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tedy_SPDB_2147915067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tedy.SPDB!MTB"
        threat_id = "2147915067"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AEFcWutvqVzjkRTLPogobwCYhy" ascii //weight: 1
        $x_1_2 = "ABysuQPvxvtPWxSdkfFUwGh" ascii //weight: 1
        $x_1_3 = "AAxFdKpurOQGDsNrD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tedy_MBXT_2147920545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tedy.MBXT!MTB"
        threat_id = "2147920545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {00 20 36 40 00 fc 31 40 00}  //weight: 3, accuracy: High
        $x_2_2 = {40 1c 40 00 17 f8 b0 00 00 ff ff ff 08 00 00 00 01 00 00 00 03 00 01 00 e9 00 00 00 a0 18 40 00 90 1a 40 00 3c 11 40 00 78 00 00 00 80 00 00 00 87}  //weight: 2, accuracy: High
        $x_1_3 = {76 79 69 6d 67 77 75 00 75 74 77 6f 6c 6f 00 00 b9 a4 b3 cc 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tedy_GPB_2147920583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tedy.GPB!MTB"
        threat_id = "2147920583"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dmnrgozxwveimgrzwvrqtebgpxatuhhylcosgdapwhazhdjbvqhyvrugpcae" ascii //weight: 1
        $x_1_2 = "jejyykuervqhewnzjohfyasspnkytioybxfq" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Tedy_EC_2147921311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tedy.EC!MTB"
        threat_id = "2147921311"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/tuiguang/qudao" ascii //weight: 1
        $x_1_2 = "taskmgr" ascii //weight: 1
        $x_1_3 = "procmgrex" ascii //weight: 1
        $x_1_4 = "proctree" ascii //weight: 1
        $x_1_5 = "pos.baidu.com" ascii //weight: 1
        $x_1_6 = "575495" ascii //weight: 1
        $x_1_7 = "<a id=x href=/wzs/" ascii //weight: 1
        $x_1_8 = ".html target=_self></a>" ascii //weight: 1
        $x_1_9 = "innerhtml" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

