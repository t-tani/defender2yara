rule TrojanDownloader_MSIL_MSILZilla_RDB_2147839818_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/MSILZilla.RDB!MTB"
        threat_id = "2147839818"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MSILZilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "e0b538cd-d7bc-4dd2-af91-4e35a820c221" ascii //weight: 1
        $x_1_2 = "LimuxTool" ascii //weight: 1
        $x_1_3 = "Eiigzs" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

