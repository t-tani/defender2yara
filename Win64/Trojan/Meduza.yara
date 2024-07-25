rule Trojan_Win64_Meduza_RPX_2147893309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Meduza.RPX!MTB"
        threat_id = "2147893309"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Meduza"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 63 6e 3c 49 03 ee 81 7d 00 50 45 00 00 74 0a b8 fe ff ff ff e9 20 02 00 00 48 89 7c 24 48 48 8d 94 24 40 07 00 00 48 89 74 24 40 45 33 c9 4c 89 bc 24 70 19 00 00 45 33 c0 45 33 ff 33 c9 4c 89 7c 24 38 4c 89 7c 24 30 c7 44 24 28 04 00 00 00 c7 44 24 20 01 00 00 00 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {49 8b df 66 44 3b 7d 06 73 4c 49 8b f7 49 63 46 3c 48 8b 0f 48 03 c6 4c 89 7c 24 20 46 8b 84 30 1c 01 00 00 42 8b 94 30 14 01 00 00 4d 03 c6 48 03 54 24 50 46 8b 8c 30 18 01 00 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

