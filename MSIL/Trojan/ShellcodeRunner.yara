rule Trojan_MSIL_ShellcodeRunner_KAA_2147895803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShellcodeRunner.KAA!MTB"
        threat_id = "2147895803"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 08 fe 0c c2 04 00 00 07 fe 0c c2 04 00 00 93 28 ?? 00 00 0a 9c 00 fe 0c c2 04 00 00 17 58 fe 0e c2 04 00 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ShellcodeRunner_SPPF_2147920004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShellcodeRunner.SPPF!MTB"
        threat_id = "2147920004"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe 0c e2 04 00 00 07 fe 0c e2 04 00 00 93 28 ?? ?? ?? 0a 9c 00 fe 0c e2 04 00 00 17 58 fe 0e e2 04 00 00 fe 0c e2 04 00 00 09 8e 69 fe 04 fe 0e e3 04 00 00 fe 0c e3 04 00 00 2d c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ShellcodeRunner_SK_2147922689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShellcodeRunner.SK!MTB"
        threat_id = "2147922689"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 05 11 06 9a 13 07 00 7e 01 00 00 04 11 04 11 07 72 96 12 00 70 72 9a 12 00 70 6f 13 00 00 0a 1f 10 28 14 00 00 0a 9c 11 04 17 58 13 04 00 11 06 17 58 13 06 11 06 11 05 8e 69 32 c3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

