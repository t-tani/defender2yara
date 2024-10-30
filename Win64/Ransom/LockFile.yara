rule Ransom_Win64_LockFile_MBK_2147795409_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/LockFile.MBK!MTB"
        threat_id = "2147795409"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "LockFile"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "winsta0\\default" ascii //weight: 1
        $x_1_2 = "YOUR FILES ARE ENCRYPTED" ascii //weight: 1
        $x_1_3 = "The price of decryption software is" ascii //weight: 1
        $x_1_4 = "We only accept Bitcoin payment" ascii //weight: 1
        $x_1_5 = {52 00 45 00 41 00 44 00 4d 00 45 00 2d 00 46 00 49 00 4c 00 45 00 [0-32] 2e 00 68 00 74 00 61 00}  //weight: 1, accuracy: Low
        $x_1_6 = {52 45 41 44 4d 45 2d 46 49 4c 45 [0-32] 2e 68 74 61}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Win64_LockFile_A_2147925023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/LockFile.A!MTB"
        threat_id = "2147925023"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "LockFile"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "encryptdecrypt" ascii //weight: 1
        $x_1_2 = ".rustsomware" ascii //weight: 1
        $x_1_3 = " pay " ascii //weight: 1
        $x_1_4 = "/rustc/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_LockFile_B_2147925024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/LockFile.B!MTB"
        threat_id = "2147925024"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "LockFile"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 ff c8 48 89 44 24 58 45 8b 2c 0e 41 8b 5c 0e 04 41 0f cd 44 33 ac 24 00 01 00 00 0f cb 33 9c 24 f8 00 00 00 41 8b 6c 0e 08 0f cd 33 ac 24 f0 00 00 00 48 89 8c 24 08 01 00 00 41 8b 74 0e 0c 0f ce 33 b4 24 28 01 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

