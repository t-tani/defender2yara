rule TrojanDownloader_MSIL_Lazy_RDF_2147890436_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Lazy.RDF!MTB"
        threat_id = "2147890436"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 08 00 00 0a 6f 09 00 00 0a 6f 0a 00 00 0a 73 0b 00 00 0a 20 a2 10 40 05 6f 0c 00 00 0a 13 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Lazy_RP_2147915041_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Lazy.RP!MTB"
        threat_id = "2147915041"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "C:\\Users\\ALIENWARE\\Downloads\\Telegram Desktop\\ConsoleApp1\\ConsoleApp1\\obj\\Debug\\" ascii //weight: 10
        $x_1_2 = "del del.bat" wide //weight: 1
        $x_1_3 = "loader20" wide //weight: 1
        $x_1_4 = "U29mdHdhcmVJbnN0YWxsZXIq" wide //weight: 1
        $x_10_5 = "_Encrypted$" wide //weight: 10
        $x_1_6 = "SoftwareInstaller.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

