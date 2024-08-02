rule TrojanDownloader_Win64_Convagent_ARA_2147917580_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Convagent.ARA!MTB"
        threat_id = "2147917580"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8d 44 24 38 48 83 7c 24 50 10 48 0f 43 44 24 38 0f b6 04 38 30 06 ff c3 48 ff c7 48 ff c6 48 83 ed 01 75 be}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

