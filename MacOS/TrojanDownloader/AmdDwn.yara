rule TrojanDownloader_MacOS_AmdDwn_A_2147921555_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/AmdDwn.A!MTB"
        threat_id = "2147921555"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "AmdDwn"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 40 03 00 00 f2 0f 2a c0 f2 0f 5e 05 cc 03 00 00 f2 0f 59 05 cc 03 00 00 f2 0f 58 05 cc 03 00 00 e8 a7 02 00 00 eb ?? 48 ?? ?? ?? e8 1a 03 00 00 f6 45 c0 01 74 ?? 48 8b 7d d0 e8 e7 02 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 df 48 89 de 31 c9 31 c0 e8 45 02 00 00 f6 45 c0 01 74 ?? 48 8b 7d d0 e8 2a 02 00 00 b8 01 00 00 00 e9 ?? ?? ?? ?? e8 39 02 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

