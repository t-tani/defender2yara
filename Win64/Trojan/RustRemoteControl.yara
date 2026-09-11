rule Trojan_Win64_RustRemoteControl_A_2147978026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RustRemoteControl.A"
        threat_id = "2147978026"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RustRemoteControl"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_12_1 = {83 fe 08 0f 84 ?? ?? ?? ?? 83 fe 09 0f 84 ?? ?? ?? ?? 83 fe 0d 74 ?? 83 fe 1b 0f 84 ?? ?? ?? ?? 83 fe 20 74 ?? 81 fe be 00 00 00 0f 85 ?? ?? ?? ?? 66 85 ed}  //weight: 12, accuracy: Low
        $x_4_2 = "auth_verifiedexecute_commandfile_actiontask_actionutility_actioninteract_action" ascii //weight: 4
        $x_4_3 = "screen_startscreen_stopwebcam_startwebcam_stop" ascii //weight: 4
        $x_4_4 = "shutdown_pcrestart_pclock_pcsleep_pcblock_inputunblock_inputhide_desktopshow_desktopget_wifi" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_12_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

