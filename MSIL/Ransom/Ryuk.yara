rule Ransom_MSIL_Ryuk_ARA_2147919300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Ryuk.ARA!MTB"
        threat_id = "2147919300"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ryuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ryukransom" ascii //weight: 2
        $x_2_2 = "RyukEncrypter" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

