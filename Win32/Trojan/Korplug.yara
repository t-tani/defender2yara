rule Trojan_Win32_Korplug_GMN_2147918622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Korplug.GMN!MTB"
        threat_id = "2147918622"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Korplug"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b e8 8b 4d ?? 8d 41 ?? 89 45 ?? 8a 44 9c ?? 8b 9c 24 ?? ?? ?? ?? 32 04 1a 88 44 29 ?? 8d 44 24 ?? 50 6a 01 52 e8 ?? ?? ?? ?? 83 c4 ?? 84 c0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

