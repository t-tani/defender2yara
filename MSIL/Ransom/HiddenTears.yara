rule Ransom_MSIL_HiddenTears_DK_2147773495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTears.DK!MTB"
        threat_id = "2147773495"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTears"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RamonJuan" ascii //weight: 1
        $x_1_2 = "bytesToBeEncrypted" ascii //weight: 1
        $x_1_3 = "EncryptDirectory" ascii //weight: 1
        $x_1_4 = "EncryptFile" ascii //weight: 1
        $x_1_5 = ".locked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_HiddenTears_AYA_2147929769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTears.AYA!MTB"
        threat_id = "2147929769"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTears"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SovietSilver Encryptor" wide //weight: 2
        $x_1_2 = "Desktop\\UI\\unlock your files.lnk" wide //weight: 1
        $x_1_3 = ".soviet" wide //weight: 1
        $x_1_4 = "$78c76961-8249-4efe-9de2-b6ef15a187f7" ascii //weight: 1
        $x_1_5 = "ssenc.Properties.Resources" wide //weight: 1
        $x_1_6 = "bytesToBeEncrypted" ascii //weight: 1
        $x_1_7 = "FileEncryption" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

