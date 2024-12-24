rule TrojanDownloader_Win32_Zusy_SIB_2147817769_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zusy.SIB!MTB"
        threat_id = "2147817769"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 08 83 c1 01 89 4d 08 8b 55 08 0f be 02 85 c0 74 ?? 8b 4d 08 8a 11 80 c2 ?? 8b 45 08 88 10}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c0 01 89 45 ?? 8b 4d 00 3b 0d ?? ?? ?? ?? 73 ?? 8b 15 ?? ?? ?? ?? 03 55 00 0f b6 02 33 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 0d 04 03 4d 00 88 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zusy_HNB_2147928956_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zusy.HNB!MTB"
        threat_id = "2147928956"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 2f 6e 65 77 2f 6e 65 74 5f 61 70 69 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 7d 00 00 00 7d 00 66 69 6c 65 00 6e 61 6d 65 00 73 69 7a 65 00 64 6f 77 6e 6c 6f 61 64 5f 75 72 6c 00}  //weight: 1, accuracy: High
        $x_2_3 = {00 6d 00 73 00 69 00 65 00 78 00 65 00 63 00 2e 00 65 00 78 00 65 00 00 00 5c 00 70 6f 77 65 72 73 68 65 6c 6c 20 2d 43 6f 6d 6d 61 6e 64 20}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

