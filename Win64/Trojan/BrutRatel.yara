rule Trojan_Win64_BrutRatel_YAE_2147924273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BrutRatel.YAE!MTB"
        threat_id = "2147924273"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BrutRatel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 48 8b 04 25 60 00 00 00 48 8b 40 18 48 8b 40 20}  //weight: 1, accuracy: High
        $x_10_2 = {48 29 c7 0f b6 44 3c ?? 42 32 04 09 48 8b 54 24 ?? 88 04 0a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

