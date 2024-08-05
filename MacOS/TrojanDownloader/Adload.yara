rule TrojanDownloader_MacOS_Adload_B_2147822253_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/Adload.B!MTB"
        threat_id = "2147822253"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 07 48 8b 4f 08 48 89 85 70 ff ff ff 48 89 8d 78 ff ff ff 48 8b 47 10 48 89 45 80 48 8b 85 e8 fe ff ff 48 8b 95 f0 fe ff ff 89 d1 29 c1 89 ce c1 ee 1f 01 ce d1 fe 48 63 f6 48 01 c6 e8 ?? ?? f8 ff 4c 8b 7d 90 48 8b 5d 98}  //weight: 1, accuracy: Low
        $x_1_2 = {66 0f 57 c0 48 8d 7d 90 66 0f 29 07 48 c7 47 10 00 00 00 00 48 89 de 4c 29 fe 48 03 b5 78 ff ff ff 48 2b b5 70 ff ff ff e8 ?? ?? ?? ff 48 8d 7d 90 48 8b 77 08 48 8b 95 70 ff ff ff 48 8b 8d 78 ff ff ff e8 ?? ?? ?? ff 4c 39 fb 74 13 48 8d 7d 90 48 8b 77 08 4c 89 fa 48 89 d9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MacOS_Adload_C_2147827625_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/Adload.C!MTB"
        threat_id = "2147827625"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 50 08 48 89 08 66 0f ef c0 66 0f 7f 85 80 fc ff ff 48 c7 ?? ?? ?? ff ff 00 00 00 00 48 83 85 e8 fe ff ff 18 ?? ?? 4c 89 e7}  //weight: 1, accuracy: Low
        $x_1_2 = "injector" ascii //weight: 1
        $x_1_3 = "keyenumerator" ascii //weight: 1
        $x_1_4 = ".cxx_destruct" ascii //weight: 1
        $x_1_5 = "_msgSendSuper2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MacOS_Adload_E_2147849297_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/Adload.E!MTB"
        threat_id = "2147849297"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.spelling.checker.Agent" ascii //weight: 1
        $x_1_2 = "/tmp/upup2" ascii //weight: 1
        $x_1_3 = "/bin/sh -c  \"/bin/chmod 777" ascii //weight: 1
        $x_1_4 = "-nobrowse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MacOS_Adload_C_2147900252_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/Adload.C"
        threat_id = "2147900252"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 44 89 c6 48 89 05 c9 13 00 00 48 8d 3d 1a 0c 00 00 ba 01 00 00 00 e8 36 06 00 00 48 8b 0d b1 13 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {2f 50 4f 53 54 00 [0-32] 65 72 72 6f 72 20 77 68 69 6c 65 20 6d 61 6b 69 6e 67 20 72 65 71 75 65 73 74 3a 20 00 00 00 00 68 74 74 70 3a 2f 2f 6d 2e}  //weight: 2, accuracy: Low
        $x_1_3 = {2e 63 6f 6d 2f 67 2f 75 70 3f 6c 66 3d 00 47 45 54}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MacOS_Adload_G_2147915881_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/Adload.G!MTB"
        threat_id = "2147915881"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 d2 90 41 0f b6 1c 16 88 1c 11 48 ff c2 49 39 d1 75 f0 4c 8b 65 90 4c 01 e8 eb 34}  //weight: 1, accuracy: High
        $x_1_2 = {45 31 ff 45 31 e4 e9 88 01 00 00 90 42 0f b6 74 2b ff 48 8b 5d 98 48 8b 45 a0 48 39 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MacOS_Adload_F_2147915945_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/Adload.F!MTB"
        threat_id = "2147915945"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 1c 31 88 1c 32 48 ff c6 49 39 f4 75 ?? 4c 8b 65 ?? 4c 8b 4d 98 4c 01 d0 44 89 c9 44 29 e1 89 ca c1 ea 1f 01 ca d1 fa 4c 63 f2 4d 01 e6}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 89 d1 48 83 e1 e0 ?? ?? ?? ?? 48 89 fe 48 c1 ee 05 48 ff c6 89 f2 83 e2 03 48 83 ff 60 0f 83 ?? ?? ?? ?? 31 ff 48 85 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MacOS_Adload_I_2147917789_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/Adload.I!MTB"
        threat_id = "2147917789"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f6 85 20 ff ff ff 01 74 ?? 48 8b bd 30 ff ff ff e8 a0 41 00 00 0f 57 c0 0f 29 85 20 ff ff ff 48 c7 85 30 ff ff ff 00 00 00 00 66 c7 85 20 ff ff ff 02 67 c6 85 22 ff ff ff 00 48 ?? ?? ?? ?? ?? ?? ba 01 00 00 00 4c 89 ee e8 55 41 00 00 f6 85 20 ff ff ff 01}  //weight: 1, accuracy: Low
        $x_1_2 = {55 48 89 e5 41 57 41 56 41 54 53 48 83 ec 60 0f 57 c0 0f 29 45 a0 48 c7 45 b0 00 00 00 00 4c ?? ?? ?? 0f 29 45 c0 48 c7 45 d0 00 00 00 00 66 c7 45 c0 02 64 c6 45 c2 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

