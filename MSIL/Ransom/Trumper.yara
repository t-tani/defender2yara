rule Ransom_MSIL_Trumper_DA_2147773128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Trumper.DA!MTB"
        threat_id = "2147773128"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Trumper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Send 0.01 Bitcoin to the following address:" ascii //weight: 1
        $x_1_2 = "DECRYPTION KEY DELETED ON:" ascii //weight: 1
        $x_1_3 = "_Trinity_Obfuscator_" ascii //weight: 1
        $x_1_4 = "Microsoft YaHei" ascii //weight: 1
        $x_1_5 = "Chromio" ascii //weight: 1
        $x_1_6 = "UH OH!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

