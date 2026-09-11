rule Backdoor_Win64_RemoteAccess_A_2147978025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/RemoteAccess.A"
        threat_id = "2147978025"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "RemoteAccess"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = "loginsbrowser_dataUSERPROFILEchromeedge" ascii //weight: 4
        $x_4_2 = "screen_startscreen_stopwebcam_startwebcam_stop" ascii //weight: 4
        $x_4_3 = {48 89 f9 e8 ?? ?? ?? ?? 48 8d 15 ?? ?? ?? ?? 48 8d 4c 24 70 41 b8 06 00 00 00 e8 ?? ?? ?? ?? 48 8d bc 24 c0 00 00 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

