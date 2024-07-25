rule Trojan_MSIL_FareIt_MBZS_2147905671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FareIt.MBZS!MTB"
        threat_id = "2147905671"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FareIt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 0b 07 17 59 0b 1f 64 07 5b 26 73 ?? 00 00 0a 0c 08}  //weight: 1, accuracy: Low
        $x_1_2 = "ordder2.Properties.Resources.resource" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

