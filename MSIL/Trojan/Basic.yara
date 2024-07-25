rule Trojan_MSIL_Basic_SK_2147852032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Basic.SK!MTB"
        threat_id = "2147852032"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Basic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 0b 17 58 13 0b 06 11 0a 11 0b 58 91 06 07 11 0b 58 91 33 05 11 0b 09 32 e6}  //weight: 2, accuracy: High
        $x_2_2 = "piri.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

