rule Trojan_Win64_Strela_GA_2147917187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Strela.GA!MTB"
        threat_id = "2147917187"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Strela"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 c7 44 24 28 88 13 00 00 48 c7 44 24 20 00 00 00 00 41 b9 10 00 00 00 31 c9 4c 89 ?? 4d 89}  //weight: 10, accuracy: Low
        $x_1_2 = {41 b8 00 30 00 00 41 b9 40 00 00 00 31 c9}  //weight: 1, accuracy: High
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Strela_GB_2147917188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Strela.GB!MTB"
        threat_id = "2147917188"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Strela"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 c7 44 24 28 88 13 00 00 48 c7 44 24 20 00 00 00 00 41 b9 10 00 00 00 31 c9}  //weight: 10, accuracy: High
        $x_1_2 = {41 b8 00 30 00 00 41 b9 40 00 00 00 31 c9}  //weight: 1, accuracy: High
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

