rule Trojan_Win64_GiaPhucStealer_CL_2147979884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GiaPhucStealer.CL!MTB"
        threat_id = "2147979884"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GiaPhucStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Login Data" ascii //weight: 1
        $x_1_2 = "\\temp_login.db" ascii //weight: 1
        $x_1_3 = "\\passwords.txt" ascii //weight: 1
        $x_1_4 = "Discord" ascii //weight: 1
        $x_1_5 = "\\Telegram Desktop\\tdata" ascii //weight: 1
        $x_1_6 = "\\Steam\\config.vdf" ascii //weight: 1
        $x_3_7 = "cmd.exe /c netsh wlan show profile" ascii //weight: 3
        $x_1_8 = "\\processes.txt" ascii //weight: 1
        $x_1_9 = "cmd.exe /c tasklist" ascii //weight: 1
        $x_3_10 = "\\GiaPhucData" ascii //weight: 3
        $x_1_11 = "\\discord_tokens.txt" ascii //weight: 1
        $x_1_12 = "\\system_info.txt" ascii //weight: 1
        $x_1_13 = "\\GiaPhuc.zip" ascii //weight: 1
        $x_3_14 = "GiaPhuc Stealer" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

