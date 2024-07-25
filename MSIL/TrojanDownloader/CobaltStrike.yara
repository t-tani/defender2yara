rule TrojanDownloader_MSIL_CobaltStrike_ACS_2147843995_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/CobaltStrike.ACS!MTB"
        threat_id = "2147843995"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {17 59 0c 17 0d 2b 2d 17 13 04 2b 1f 02 11 04 09 6f 16 00 00 0a 13 05 06 12 05 28 17 00 00 0a 6f 18 00 00 0a 26 11 04 17 58 13 04 11 04 07 31 dc 09 17 58 0d 09 08 31 cf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

