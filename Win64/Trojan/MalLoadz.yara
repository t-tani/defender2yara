rule Trojan_Win64_MalLoadz_A_2147922660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MalLoadz.A!MTB"
        threat_id = "2147922660"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MalLoadz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c4 04 89 45 fc 8b 4d 08 0f be 11 03 55 fc 89 55 fc 8b 45 08 83 c0 01 89 45 08 8b 4d 08 0f be}  //weight: 1, accuracy: High
        $x_1_2 = {41 0f b6 11 4d 8d 49 01 41 0f b6 ca 41 ff ca 80 e1 03 d2 ca 42 8d 04 01 32 d0 41 88 51 ff 49 83 eb 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

