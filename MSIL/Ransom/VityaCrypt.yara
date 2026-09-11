rule Ransom_MSIL_VityaCrypt_PC_2147978092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/VityaCrypt.PC!MTB"
        threat_id = "2147978092"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VityaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".vitek" wide //weight: 1
        $x_1_2 = "VityaRansom_" wide //weight: 1
        $x_3_3 = {4f 00 4f 00 50 00 53 00 20 00 59 00 4f 00 55 00 20 00 48 00 41 00 56 00 45 00 [0-21] 46 00 55 00 43 00 4b 00 45 00 44 00 20 00 42 00 59 00 20 00 56 00 49 00 54 00 59 00 41 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

