rule Trojan_Win32_Yogi_A_2147979773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Yogi.A!MTB"
        threat_id = "2147979773"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Yogi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {83 bd bc fd ff ff 07 8d 85 a8 fd ff ff 68 0c 52 00 10 0f 47 85 a8 fd ff ff 50 8d 85 a4 fd ff ff c7 85 a4 fd ff ff 00 00 00 00 50 ff 15 ?? ?? ?? ?? 83 c4 0c 85 c0}  //weight: 20, accuracy: Low
        $x_10_2 = {66 0f 13 85 74 fe ff ff 0f 11 85 7c fe ff ff c7 85 48 ff ff ff 00 00 00 00 0f 11 85 38 ff ff ff c7 85 4c ff ff ff 00 00 00 00 e8 ?? ?? ?? ?? 83 bd 1c ff ff ff 07 8d 85 08 ff ff ff ff b5 18 ff ff ff 0f 47 85 08 ff ff ff 8d 8d 38 ff ff ff}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

