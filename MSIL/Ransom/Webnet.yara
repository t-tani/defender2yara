rule Ransom_MSIL_Webnet_AMTB_2147979990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Webnet!AMTB"
        threat_id = "2147979990"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Webnet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SYSTEM LOCKED" ascii //weight: 1
        $x_1_2 = "Global\\WebNetMutex_MOLAXES_7A3F" ascii //weight: 1
        $x_1_3 = "webnet_alarm.wav" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WebNet" ascii //weight: 1
        $x_1_5 = "DESTRUCTION IN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

