rule Trojan_Win64_AstarionRAT_GV_2147979851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AstarionRAT.GV!MTB"
        threat_id = "2147979851"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AstarionRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f be 04 01 48 8b 4c 24 30 48 8b 54 24 70 48 03 d1 48 8b ca 0f b6 09 33 c8 8b c1 48 8b 4c 24 30 48 8b 54 24 70 48 03 d1 48 8b ca 88 01 eb a2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

