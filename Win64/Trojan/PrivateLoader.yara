rule Trojan_Win64_PrivateLoader_RPZ_2147851170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PrivateLoader.RPZ!MTB"
        threat_id = "2147851170"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PrivateLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 33 c9 8b 54 24 6c 41 c7 c0 00 10 00 00 41 c7 c1 40 00 00 00 48 8b 44 24 40 ff d0 48 89 c3 48 89 d9 48 8d 96 fb 5b 04 00 44 8b 44 24 6c 41 81 e8 fb 5b 04 00 48 8b 44 24 38 ff d0 48 89 f9 48 8b 44 24 48 ff d0 4c 89 e9 48 8b 44 24 48 ff d0 48 89 de ff d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_PrivateLoader_RPQ_2147851171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PrivateLoader.RPQ!MTB"
        threat_id = "2147851171"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PrivateLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 83 c4 20 48 83 c9 ff ff d0 48 8b c3 b9 3c 03 00 00 80 00 08 e9 85 00 00 00 00 00 75 f4 ff d3 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_PrivateLoader_RPY_2147889444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PrivateLoader.RPY!MTB"
        threat_id = "2147889444"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PrivateLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d9 41 b9 40 00 00 00 48 8d 4d 10 41 b8 e8 03 00 00 48 89 4c 24 20 48 8b d3 48 83 c9 ff ff d0 48 8b c3 b9 3c 03 00 00 80 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_PrivateLoader_NPR_2147898627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PrivateLoader.NPR!MTB"
        threat_id = "2147898627"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PrivateLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c7 45 e0 48 8b c4 48 eb 2e 36 00 00 0f b7 41 ?? 3d 0b 01 00 00 0f 84 f4 36 00 00 3d ?? ?? ?? ?? 0f 85 e2 36 00 00 33 c0 83 b9 84 00 00 00 0e}  //weight: 5, accuracy: Low
        $x_5_2 = {44 8b e3 33 c0 48 03 cf 48 8d 55 e0 41 b8 ?? ?? ?? ?? e8 b1 05 00 00 85 c0 74 14}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_PrivateLoader_NR_2147898653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PrivateLoader.NR!MTB"
        threat_id = "2147898653"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PrivateLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {80 00 09 48 ff c0 48 83 e9 ?? 75 f4 ff d3 48 8b 5c 24 ?? 33 c0 48 8b 7c 24 ?? 48 83 c4 50}  //weight: 5, accuracy: Low
        $x_5_2 = {48 3b ca 74 1e 40 84 79 ?? 74 18 48 8b 40 ?? eb 2b 05 ae dd ff ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

