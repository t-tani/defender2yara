rule Trojan_MSIL_RisePro_KAB_2147902685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RisePro.KAB!MTB"
        threat_id = "2147902685"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RisePro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 30 61 d2 81 ?? 00 00 01 03 50 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

