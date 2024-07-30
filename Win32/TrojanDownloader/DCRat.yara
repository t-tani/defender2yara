rule TrojanDownloader_Win32_DCRat_A_2147917300_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/DCRat.A!MTB"
        threat_id = "2147917300"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 8b c8 8b 45 ?? 8b 10 8b 42 ?? 66 0f b6 14 18 33 ca}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

