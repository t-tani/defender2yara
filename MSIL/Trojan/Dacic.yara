rule Trojan_MSIL_Dacic_SK_2147895743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dacic.SK!MTB"
        threat_id = "2147895743"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 7b 0c 00 00 04 7b 27 00 00 04 07 17 58 0e 04 07 9a 05 6f ?? ?? ?? 06 07 9a 28 ?? ?? ?? 06 6f ?? ?? ?? 06 07 17 58 0b 07 6e 0e 04 8e 69 6a 32 cf}  //weight: 2, accuracy: Low
        $x_2_2 = "\\charmhost\\obj\\Release\\charmhost.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dacic_GMN_2147907889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dacic.GMN!MTB"
        threat_id = "2147907889"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {69 11 0d 20 ?? ?? ?? ?? 61 58 8d ?? ?? ?? ?? 13 0c 20 ?? ?? ?? e8 11 0d 5a 39 ?? ?? ?? ?? 11 08 11 0d 20 ?? ?? ?? ?? 64 13 0d 11 0c 11 0d 20 ?? ?? ?? e8 59 13 0d 11 0d 20 ?? ?? ?? 1b 61 6f ?? ?? ?? 0a 11 0c 11 08 8e 11 0d 20 ?? ?? ?? ?? 59 13 0d 69 11 0d 20 ?? ?? ?? 7c 61 13 0d d0 ?? ?? ?? ?? 20 ?? ?? ?? f5 11 0d 61 13 0d 28 ab 00 00 0a 11 0d 20 0d 82 87 fb 61 13 0d a2 20 ?? ?? ?? b6 11 0d 20 1f 00 00 00 5f 62}  //weight: 10, accuracy: Low
        $x_1_2 = "PLoader.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dacic_ND_2147916581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dacic.ND!MTB"
        threat_id = "2147916581"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {25 06 93 0b 06 18 58 93 07 61 0b}  //weight: 5, accuracy: High
        $x_3_2 = "67134.90134.56.09" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

