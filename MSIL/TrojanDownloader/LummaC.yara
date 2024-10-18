rule TrojanDownloader_MSIL_LummaC_CCJC_2147924101_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/LummaC.CCJC!MTB"
        threat_id = "2147924101"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 04 11 04 09 17 73 ?? ?? ?? ?? 13 05 11 05 02 16 02 8e 69 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 10 00 de 18 11 05 2c 07 11 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

