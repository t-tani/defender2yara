rule Trojan_Win64_LummaC_AA_2147898573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaC.AA!MTB"
        threat_id = "2147898573"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 04 24 8b 54 24 18 48 8b 4c 24 08 4c 63 44 24 1c 42 8b 0c 81 4c 63 c1 42 33 14 80 48 63 c9 89 14 88 8b 44 24 1c 83 c0 01 89 44 24 1c e9 bf ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

