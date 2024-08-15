rule Trojan_MSIL_Darktortilla_NB_2147918800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Darktortilla.NB!MTB"
        threat_id = "2147918800"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Darktortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {02 1f 49 61 b4 0a 18 0d 2b b5 02 0a 18 0d 2b af}  //weight: 5, accuracy: High
        $x_5_2 = {26 16 0d 2b d0 03 1d 5d 16 fe 01 0b 07}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

