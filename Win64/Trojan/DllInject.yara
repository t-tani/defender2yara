rule Trojan_Win64_DllInject_C_2147794456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllInject.C!MTB"
        threat_id = "2147794456"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff c9 8b c1 d1 e8 0b c8 8b c1 c1 e8 02 0b c8 8b c1 c1 e8 04 0b c8 8b c1 c1 e8 08 0b c8 8b c1 c1 e8 10 0b c1 ff c0}  //weight: 1, accuracy: High
        $x_1_2 = "BlackBone.sys" ascii //weight: 1
        $x_1_3 = "NivesroLoader.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DllInject_NEAC_2147842643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllInject.NEAC!MTB"
        threat_id = "2147842643"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {03 c2 83 e0 1f 2b c2 48 98 48 8b 8c 24 00 03 00 00 0f b6 04 01 8b 8c 24 34 03 00 00 33 c8 8b c1 48 63 8c 24 30 03 00 00 48 8b 94 24 28 03 00 00 88 04 0a eb 82}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DllInject_RPX_2147843659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllInject.RPX!MTB"
        threat_id = "2147843659"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 43 38 2d ?? ?? ?? ?? 09 43 78 8b 43 44 48 8b 8b b8 00 00 00 42 31 04 09 49 83 c1 04 8b 83 cc 00 00 00 01 43 44 8b 4b 40 2b 8b a8 00 00 00 01 8b b0 00 00 00 8b 4b 54 81 e9 ?? ?? ?? ?? 01 8b f8 00 00 00 49 81 f9 ec e2 01 00 7c b3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DllInject_CXIV_2147848932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllInject.CXIV!MTB"
        threat_id = "2147848932"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\nitronet\\nitrogen\\x64\\Release - msi.dll\\Nitrogen.pdb" ascii //weight: 1
        $x_1_2 = "Time Trigger" wide //weight: 1
        $x_1_3 = "Idle Trigger" wide //weight: 1
        $x_1_4 = "Daily Trigger" wide //weight: 1
        $x_1_5 = "AVNitrogenTarget@@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DllInject_MA_2147851698_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllInject.MA!MTB"
        threat_id = "2147851698"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 33 c0 48 ff c0 c3 74 24 10 57 48 83 ec 20 49 8b f8 8b da 48 8b f1 83 fa 01 75 05 e8 ?? ?? ?? ?? 4c 8b c7 8b d3 48 8b ce 48 8b 5c 24 30 48 8b 74 24 38 48 83 c4 20 5f e9 a7 fe ff ff}  //weight: 5, accuracy: Low
        $x_2_2 = {22 20 0b 02 0a 00 00 96 25 00 00 c4 08 00 00 00 00 00 ac 73 21}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DllInject_MB_2147851937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllInject.MB!MTB"
        threat_id = "2147851937"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {4b 8d 2c 09 48 81 ea 00 00 01 00 49 ff c1 48 89 d1 66 81 e2 ff 03 48 c1 f9 0a 66 81 ea 00 24 66 81 e9 00 28 66 89 54 28 02 66 89 0c 28 49 ff c1 e9}  //weight: 5, accuracy: High
        $x_1_2 = "LockDownProtectProcessById" ascii //weight: 1
        $x_1_3 = "NimMain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DllInject_PD_2147905723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllInject.PD!MTB"
        threat_id = "2147905723"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 02 41 88 00 88 0a 0f b6 54 24 31 44 0f b6 44 24 30 0f b6 4c 14 32 42 02 4c 04 32 0f b6 c1 0f b6 4c 04 32 42 32 4c 16 f7 41 88 4a ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DllInject_ME_2147907734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllInject.ME!MTB"
        threat_id = "2147907734"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DLL-Sideloading" ascii //weight: 1
        $x_1_2 = {41 b9 40 00 00 00 41 b8 00 10 00 00 48 8b d6 33 c9 ff d0 4c 8b c6 48 8b d7 48 8b c8 48 8b d8 e8 04 0e 00 00 ff d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DllInject_RTS_2147926437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllInject.RTS!MTB"
        threat_id = "2147926437"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 ff c1 48 f7 e1 48 8b c1 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 04 48 6b c0 17 48 2b c8 49 0f af cb 8a 44 0c 20 42 32 04 17 41 88 02 49 ff c2 44 3b cb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DllInject_HTS_2147926459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllInject.HTS!MTB"
        threat_id = "2147926459"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 41 10 65 48 8b 04 25 30 00 00 00 48 8b 48 60 48 8b 05 ?? ?? ?? ?? 48 89 08 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

