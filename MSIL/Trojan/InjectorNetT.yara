rule Trojan_MSIL_InjectorNetT_AGHA_2147929009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/InjectorNetT.AGHA!MTB"
        threat_id = "2147929009"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "InjectorNetT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {59 91 61 03 08 20 0a 02 00 00 58 20 09 02 00 00 59 1e 59 1e 58 03 8e 69 5d 1f 09 58 1f 0d 58 1f 16 59 91 59 20 fa 00 00 00 58 1c 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

