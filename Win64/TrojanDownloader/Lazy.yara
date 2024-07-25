rule TrojanDownloader_Win64_Lazy_RDA_2147835630_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Lazy.RDA!MTB"
        threat_id = "2147835630"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b8 33 01 00 00 66 03 c2 66 33 c1}  //weight: 2, accuracy: High
        $x_2_2 = {48 63 c2 48 8d 4d ?? 48 03 c8 8d 42 ?? 30 01 ff c2 83 fa}  //weight: 2, accuracy: Low
        $x_1_3 = "wasd-" ascii //weight: 1
        $x_1_4 = "//cdn.discordapp.com/attachments" ascii //weight: 1
        $x_1_5 = "chrome.exe" ascii //weight: 1
        $x_1_6 = "Fortnite" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

