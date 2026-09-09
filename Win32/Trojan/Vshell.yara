rule Trojan_Win32_Vshell_AH_2147977880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vshell.AH!MTB"
        threat_id = "2147977880"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {51 c7 45 f4 75 73 65 72 c7 45 f8 33 32 2e 64 66 c7 45 fc 6c 6c c6 45 fe 00 ff d0 b9 45 83 56 07 e8 ?? ?? ?? ?? 89 46 04 8d 45 e8 50 c7 45 e8 77 73 32 5f c7 45 ec 33 32 2e 64 66 c7 45 f0 6c 6c c6 45 f2 00 ff 16 8d 45 dc c7 45 dc 6d 73 76 63 50 c7 45 e0 72 74 2e 64 66 c7 45 e4 6c 6c c6 45 e6 00 ff 16}  //weight: 2, accuracy: Low
        $x_1_2 = {b9 75 6e 4d 61 89 46 1c e8 ?? ?? ?? ?? b9 a9 28 34 80 89 46 20 e8 ?? ?? ?? ?? b9 12 1e 7b 4d 89 46 24 e8 ?? ?? ?? ?? b9 d9 da 13 ff 89 46 28 e8 ?? ?? ?? ?? b9 d9 d9 43 ed 89 46 2c e8 ?? ?? ?? ?? b9 99 dd 6b ed 89 46 34}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

