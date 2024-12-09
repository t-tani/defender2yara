rule Trojan_Win64_BlackWidow_RPZ_2147910377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.RPZ!MTB"
        threat_id = "2147910377"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 05 00 30 00 00 48 8b 8c 24 f0 00 00 00 48 89 81 b0 00 00 00 8b 44 24 44 35 1b 0f 00 00 89 44 24 44 8b 44 24 50 35 ca 05 00 00 89 84 24 84 00 00 00 8b 44 24 54 2d 29 05 00 00 89 84 24 80 00 00 00 8b 44 24 54 05 b1 00 00 00 89 44 24 7c 8b 44 24 4c 35 74 0a 00 00 89 44 24 78 8b 44 24 4c 05 6f 05 00 00 89 44 24 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_RPX_2147910378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.RPX!MTB"
        threat_id = "2147910378"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 8c 24 c0 00 00 00 8b 89 dc 00 00 00 33 c8 8b c1 48 8b 8c 24 c0 00 00 00 89 81 dc 00 00 00 48 63 44 24 3c 48 8b 8c 24 c0 00 00 00 48 8b 89 b0 00 00 00 48 8b 94 24 c0 00 00 00 8b 52 5c 8b 04 81 33 c2 48 63 4c 24 3c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_RPY_2147910379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.RPY!MTB"
        threat_id = "2147910379"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 44 24 30 8b 40 20 48 8b 4c 24 70 48 03 c8 48 8b c1 8b 4c 24 20 48 8d 04 88 48 89 44 24 38 48 8b 44 24 38 8b 00 48 8b 4c 24 70 48 03 c8 48 8b c1 48 89 44 24 28 48 8b 4c 24 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_GA_2147927843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.GA!MTB"
        threat_id = "2147927843"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 31 d2 49 f7 f0 45 8a 14 11 44 30 14 0f 48 ff c1 48 89 c8 48 81 f9 a7 8c 0a 00 76 e3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

