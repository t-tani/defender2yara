rule Trojan_Win32_Malex_ASG_2147917448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Malex.ASG!MTB"
        threat_id = "2147917448"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Malex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {ba 02 00 00 00 8a 84 15 ?? ?? ff ff 84 c0 74 22 8a 8d ?? ?? ff ff 32 8d ?? ?? ff ff 80 c9 50 30 c1 88 8c 15 ?? ?? ff ff 42 eb}  //weight: 3, accuracy: Low
        $x_2_2 = {85 c0 89 85 ?? fb ff ff 19 c0 f7 d8 8d 85 ?? fb ff ff 6a 10 50 ff b5}  //weight: 2, accuracy: Low
        $x_1_3 = "{%04X-8B9A-11D5-EBA1-F78EEEEEE983}" ascii //weight: 1
        $x_1_4 = "%d processes killed OK" ascii //weight: 1
        $x_1_5 = "reboot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

