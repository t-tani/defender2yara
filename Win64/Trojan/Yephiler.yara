rule Trojan_Win64_Yephiler_AHB_2147974467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Yephiler.AHB!MTB"
        threat_id = "2147974467"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Yephiler"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "zerin_file_encrypt_v1" ascii //weight: 30
        $x_20_2 = "Global\\ZerinAgentLock" ascii //weight: 20
        $x_10_3 = "Global\\ZerinElevOK" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Yephiler_A_2147977616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Yephiler.A!MTB"
        threat_id = "2147977616"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Yephiler"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {8b c8 80 e1 01 f6 d9 1a c9 80 e1 51 80 c1 71 32 0c 06 88 4c 04 10 40 3b c2}  //weight: 20, accuracy: High
        $x_15_2 = {0f b6 44 0c 10 66 89 84 4c 1c 03 00 00 41 80 7c 0c 10 00}  //weight: 15, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Yephiler_MK_2147979420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Yephiler.MK!MTB"
        threat_id = "2147979420"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Yephiler"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_35_1 = {48 8b 44 24 08 48 8b 4c 24 20 48 03 c8 48 8b c1 0f b6 00 48 6b 4c 24 08 07 48 8b 54 24 08 48 83 f2 07 48 33 ca 0f b6 c9 83 c1 7a 33 c1 88 04 24 48 8b 44 24 08 48 8b 4c 24 28 48 03 c8 48 8b c1}  //weight: 35, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

