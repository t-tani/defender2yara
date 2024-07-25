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

