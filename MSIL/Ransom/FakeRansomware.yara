rule Ransom_MSIL_FakeRansomware_AFK_2147921642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FakeRansomware.AFK!MTB"
        threat_id = "2147921642"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FakeRansomware"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "FakeRansomware1.0\\obj\\Debug\\FakeRansomware1.0.pdb" ascii //weight: 2
        $x_1_2 = "Your all files are encrypted by The Encrypter Ransomware v2.34" wide //weight: 1
        $x_1_3 = "You have to pay $1500 to free all of your files. If you pay less that this, some of yor files will be PERMANENTLY DELETED" wide //weight: 1
        $x_1_4 = "Or, type our Ransomware password" wide //weight: 1
        $x_2_5 = "https://www.ransom.encrypter.com/info" wide //weight: 2
        $x_1_6 = "FakeRansomware1.0" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

