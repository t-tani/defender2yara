rule Trojan_Win64_VIPKeyLogger_GXM_2147975791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VIPKeyLogger.GXM!MTB"
        threat_id = "2147975791"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VIPKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {e9 03 00 00 00 cc cc cc 40 53 48 83 ec 20 48 8b d9 45 85 c0 74 08 45 8b c0 e8 e2}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_VIPKeyLogger_GXT_2147977728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VIPKeyLogger.GXT!MTB"
        threat_id = "2147977728"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VIPKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {41 8b c9 8b d0 d3 ea 80 e2 0f 80 fa 0a 1a c9 41 83 e9 04 80 e1 d9 80 c1 57 02 ca 42 88 4c 04 78 49 ff c0 49 83 f8 08}  //weight: 4, accuracy: High
        $x_2_2 = "Software\\Microsoft\\Windows NT\\CurrentVersion" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_VIPKeyLogger_GB_2147977729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VIPKeyLogger.GB!MTB"
        threat_id = "2147977729"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VIPKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VIP Recovery" ascii //weight: 1
        $x_1_2 = "\\Kometa\\User Data\\Default\\Network\\Cookies" ascii //weight: 1
        $x_1_3 = "\\Sputnik\\Sputnik\\User Data\\Default\\Web Data" ascii //weight: 1
        $x_1_4 = "\\Chedot\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_5 = "Card Number" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

