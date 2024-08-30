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

