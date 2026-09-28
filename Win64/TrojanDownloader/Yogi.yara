rule TrojanDownloader_Win64_Yogi_ARA_2147978983_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Yogi.ARA!MTB"
        threat_id = "2147978983"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Yogi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "WinHCheck.exe" ascii //weight: 2
        $x_2_2 = "powershell.exe -ExecutionPolicy Bypass -File" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

