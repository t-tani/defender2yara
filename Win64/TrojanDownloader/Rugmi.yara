rule TrojanDownloader_Win64_Rugmi_AS_2147901328_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Rugmi.AS!MTB"
        threat_id = "2147901328"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 44 24 ?? 48 8b 8c 24 ?? ?? ?? ?? 48 03 c8 48 8b c1 48 89 84 24 ?? ?? ?? ?? 48 8b 84 24 ?? ?? ?? ?? 8b 8c 24 ?? ?? ?? ?? 8b 00 33 c1 48 8b 8c 24 ?? ?? ?? ?? 89 01 8b 44 24 ?? 83 c0 ?? 89 44 24 ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_Rugmi_AA_2147901369_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Rugmi.AA!MTB"
        threat_id = "2147901369"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "U:\\rout\\x64\\release\\5bC\\a2j\\llq.pdb" ascii //weight: 10
        $x_1_2 = "TweakScheduler" wide //weight: 1
        $x_1_3 = "https://bitsum.com/check.php" wide //weight: 1
        $x_1_4 = "prolasso.key" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_Rugmi_EC_2147908399_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Rugmi.EC!MTB"
        threat_id = "2147908399"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 35 33 26 af 22 48 89 c2 48 c1 c2 07 31 c2 0f b7 c2 48 01 c8 c3}  //weight: 5, accuracy: High
        $x_5_2 = {48 89 c2 48 d1 c2 48 31 c2 48 89 d0 48 c1 c0 02 31 d0 0f b7 c0 48 01 c8 c3}  //weight: 5, accuracy: High
        $x_1_3 = "rs-shell-main\\kundalini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_Rugmi_HNT_2147909712_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Rugmi.HNT!MTB"
        threat_id = "2147909712"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 69 c0 3f 00 01 00 48 83 c2 02 0f b7 c8 44 03 c1 49 83 e9 01 75 d9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_Rugmi_HNH_2147909880_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Rugmi.HNH!MTB"
        threat_id = "2147909880"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 44 24 10 8a 00 48 8b 4c 24 08 88 01 48 8b 44 24 08 48 83 c0 01 48 89 44 24 08 48 8b 44 24 10 48 83 c0 01 48 89 44 24 10}  //weight: 1, accuracy: High
        $x_1_2 = {48 89 54 24 08 48 89 4c 24 10 48 8b 44 24 10 48 89 04 24 48}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_Rugmi_HNG_2147909896_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Rugmi.HNG!MTB"
        threat_id = "2147909896"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 54 8b 44 24 08 48 8b 4c 24 30 48 03 c8 48 8b c1 8b 4c 24 04 0f b6 04 08 88 44 24 02}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_Rugmi_HNL_2147912835_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Rugmi.HNL!MTB"
        threat_id = "2147912835"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b8 00 10 00 00 ba 0a 02 00 00 33 c9 48 8b 84 24 ?? ?? 00 00 ff 50}  //weight: 1, accuracy: Low
        $x_1_2 = {00 48 8d 54 24 ?? 48 8d 4c 24 ?? 48 8b 84 24 ?? ?? 00 00 ff (50|10)}  //weight: 1, accuracy: Low
        $x_1_3 = {ff 50 10 48 8b 84 24 ?? ?? 00 00 8b 4c 24 ?? 89 08 48 8d 4c 24 ?? e8 ?? ?? ?? ?? 89 44 24 ?? 48 8b 8c 24 ?? ?? 00 00 ff 51}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_Rugmi_HNM_2147912836_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Rugmi.HNM!MTB"
        threat_id = "2147912836"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 89 44 24 08 8b 44 24 30 89 04 24 8b 44 24 30 ff c8 89 44 24 30 83 3c 24 00 74 2b 48 8b 44 24 20 48 8b 4c 24 28 0f b6 09 88 08 48 8b 44 24 20 48 ff c0 48 89 44 24 20 48 8b 44 24 28 48 ff c0 48 89 44 24 28 eb be}  //weight: 10, accuracy: High
        $x_1_2 = {8b d6 48 03 e8 ff 54 24 ?? 44 8b c6 48 8b d5 48 8b c8 48 8b d8 e8 ?? ?? ?? ?? 4c 8b a4 24 ?? 00 00 00 4c 8d 8c 24 ?? 00 00 00 33 c0 8b d6 48 8b cd 49 89 9c 24 ?? ?? 00 00 48 8b 5c 24 ?? 89 84 24 ?? 00 00 00 45 8b [0-5] ff d3}  //weight: 1, accuracy: Low
        $x_1_3 = {b9 40 00 00 00 48 63 50 3c 8b ?? 02 2c [0-4] 03 ?? ff [0-4] 8b ?? 48 8b ?? 48 8b ?? 48 8b ?? e8 [0-32] 49 89 [0-2] c0 0c 00 00 [0-32] ff d3 [0-18] e8 [0-32] ff d3}  //weight: 1, accuracy: Low
        $x_1_4 = {b9 40 00 00 00 48 63 50 3c ?? 8b ?? 02 2c [0-4] 03 ?? ff [0-4] 8b ?? ?? 8b ?? 48 8b ?? 48 8b ?? e8 [0-32] 49 89 [0-4] 00 00 [0-32] ff d3 [0-18] e8 [0-32] ff d3}  //weight: 1, accuracy: Low
        $x_1_5 = {b9 40 00 00 00 48 63 50 3c ?? 8b ?? 02 2c [0-4] 03 ?? ff [0-4] 8b ?? ?? 8b ?? 48 8b ?? 48 8b ?? e8 [0-32] 49 89 [0-4] 00 00 [0-32] ff d4 [0-18] e8 [0-32] ff d4}  //weight: 1, accuracy: Low
        $x_1_6 = {b9 40 00 00 00 [0-4] 63 ?? 3c ?? 8b ?? ?? 2c [0-4] 03 ?? ff 94 24 ?? ?? 00 00 [0-16] 48 [0-16] e8 [0-34] 89 [0-8] 00 00 [0-32] ff 94 24 [0-2] 00 00 [0-18] e8 [0-32] ff 94 24 [0-2] 00 00}  //weight: 1, accuracy: Low
        $x_1_7 = {b9 40 00 00 00 ff d0 [0-32] e8 [0-24] c0 0c 00 00 [0-64] ff d0 [0-41] e8 [0-41] ff d0}  //weight: 1, accuracy: Low
        $x_1_8 = {48 63 48 3c 8b [0-14] 2c [0-18] 00 00 00 00 00 00 [0-14] 41 ff d4 [0-7] 8b [0-7] e8 [0-7] 24 ?? ?? 00 00 [0-7] 24 ?? ?? 00 00 [0-21] 8b [0-21] 41 ff d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win64_Rugmi_HNO_2147912931_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Rugmi.HNO!MTB"
        threat_id = "2147912931"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 08 00 00 00 48 03 95 ?? ?? 00 00 8b 4d ?? 89 8d ?? ?? 00 00 48 89 c1 8b 85 02 00 00 41 89 c0 e8 ?? ?? 00 00 48 89 85 ?? ?? 00 00 c7 45 ?? 00 00 00 00 c7 45 ?? 00 00 00 00 c7 45 ?? 00 00 00 00 8b 45 07 8b 55 ?? 3b c2 73 36 8b 45 07 48 63 c0 48 03 85 ?? ?? 00 00 48 89 85 ?? ?? 00 00 48 8b 85 ?? ?? 00 00 8b 55 ?? 33 10 48 8b 85 ?? ?? 00 00 89 10 b8 04 00 00 00 03 45 07 89 45 07 eb c0 48 8b 85 ?? ?? 00 00 48 89 85 ?? ?? 00 00 48 8b 85 ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_Rugmi_HNP_2147914872_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Rugmi.HNP!MTB"
        threat_id = "2147914872"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b8 00 10 00 00 [0-48] 04 01 [0-176] c7 44 24 ?? 00 00 00 00 c7 44 24 ?? 80 00 00 00 [0-8] c7 44 24 ?? 03 00 00 00 ff [0-240] 0f 6f 40 [0-3] 83 [0-8] 0f 11 40 [0-240] 63 ?? 3c [0-4] 89 [0-5] 8b ?? ?? 2c [0-43] ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_Rugmi_HNQ_2147914873_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Rugmi.HNQ!MTB"
        threat_id = "2147914873"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 b8 00 10 00 00 [0-21] ff 15 [0-64] b8 04 01 00 00 [0-244] c7 44 24 30 00 00 00 00 c7 44 24 28 80 00 00 00 [0-48] ff 15}  //weight: 5, accuracy: Low
        $x_1_2 = {48 63 40 3c 48 8b 8c 24 ?? 00 00 00 48 03 c8 48 8b c1 48 89 84 24 ?? 00 00 00 48 8b 84 24 ?? 00 00 00 8b 40 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_Rugmi_AZ_2147921335_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Rugmi.AZ!MTB"
        threat_id = "2147921335"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {f3 0f 6f 00 83 c2 10 66 0f fe c1 f3 0f 7f 00 f3 0f 6f 40 10 66 0f fe c1 f3 0f 7f 40 10 f3 0f 6f 40 20 66 0f fe c1 f3 0f 7f 40 20 f3 0f 6f 40 30 66 0f fe c1 f3 0f 7f 40 30 48 83 c0 40 41 3b d1 72}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

