rule TrojanDownloader_MSIL_Jalapeno_AYB_2147926814_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Jalapeno.AYB!MTB"
        threat_id = "2147926814"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "bc.yui5.ru.com" wide //weight: 2
        $x_1_2 = "m8DCAB8" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "VirtualProtect" ascii //weight: 1
        $x_1_6 = "DebuggableAttribute" ascii //weight: 1
        $x_1_7 = "TripleDESCryptoServiceProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

