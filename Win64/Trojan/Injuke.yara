rule Trojan_Win64_Injuke_CRUV_2147848209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injuke.CRUV!MTB"
        threat_id = "2147848209"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 44 24 18 8b 44 24 08 99 83 e0 ?? 33 c2 2b c2 85 c0 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injuke_CRUW_2147848211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injuke.CRUW!MTB"
        threat_id = "2147848211"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 74 99 83 e0 ?? 33 c2 2b c2 85 c0 74 ?? 8b 44 24 74 ff c0 89 44 24 74 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

