rule Backdoor_Win64_Multiverze_A_2147978027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Multiverze.A"
        threat_id = "2147978027"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Multiverze"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {41 b9 0b 00 00 00 4c 89 f1 4c 89 fa e8 ?? ?? ?? ?? 84 c0 74 1b 49 8b 45 00 31 c9 86 48 10 48 8d 8c 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? e9 ?? ?? ?? ?? 4c 8d 05 ?? ?? ?? ?? 41 b9 0c 00 00 00 4c 89 f1 4c 89 fa e8 ?? ?? ?? ?? 84 c0 0f 84 ?? ?? ?? ?? 49 8b 6c 24 18 8a 45 ?? 84 c0 75 c2 b0 01}  //weight: 10, accuracy: Low
        $x_10_2 = {41 b8 0a 00 00 00 4c 89 f1 e8 ?? ?? ?? ?? 4c 8b 7b 08 48 8b 43 10 48 8d 0d ?? ?? ?? ?? 49 89 0c 24 49 c7 44 24 08 0a 00 00 00 48 8d 0d ?? ?? ?? ?? 49 89 4c 24 10 49 c7 44 24 18 0f 00 00 00 48 8d 0d ?? ?? ?? ?? 49 89 4c 24 20 49 c7 44 24 28 08 00 00 00 4d 89 7c 24 30 49 89 44 24 38}  //weight: 10, accuracy: Low
        $x_4_3 = "auth_verifiedexecute_commandfile_actiontask_actionutility_actioninteract_actionnotification_actionsettings_actionclipboard_actionadvanced_actionstream_actionaudio_action" ascii //weight: 4
        $x_4_4 = "powershell-NoProfile-NonInteractive-CommandtitleSystem Message" ascii //weight: 4
        $x_4_5 = "screen_startscreen_stopwebcam_startwebcam_stop" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_4_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

