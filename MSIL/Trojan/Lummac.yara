rule Trojan_MSIL_Lummac_GPC_2147918271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lummac.GPC!MTB"
        threat_id = "2147918271"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lummac"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 08 06 09 91 9c 06 09 11 ?? 9c 06 08 91 06 09 91 58 20 00 01 00 00 5d [0-47] 91 61 d2 81 1d 00 00 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

