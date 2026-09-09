rule Trojan_Win64_RevStealer_DA_2147975158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RevStealer.DA!MTB"
        threat_id = "2147975158"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RevStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 45 8a dd 45 8b d5 41 8d 52 06 8d 42 fe 41 23 c6 7d 09 41 2b c4 83 c8 f8 41 03 c4 8a c8 45 8a c1 41 d2 e8 8d 4a ff 41 23 ce 7d 09 41 2b cc 83 c9 f8 41 03 cc 41 8a c1 d2 e8 8d 4a 01 44 32 c0 41 23 ce 7d 09 41 2b cc 83 c9 f8 41 03 cc 41 8a c1 d2 e8 44 32 c0 41 23 d6 7d 09 41 2b d4 83 ca f8 41 03 d4 8a ca 41 8a c1 d2 e8 41 8a ca 44 32 c0 41 8a c1 d2 e8 41 8b ca 44 32 c0 45 03 d4 b8 63 00 00 00 d3 f8 44 32 c0 45 22 c4 41 d2 e0 45 0a d8 44 3b}  //weight: 1, accuracy: High
        $x_1_2 = {45 32 ed 41 0f b6 f5 41 fe c5 44 8a 44 b5 01 44 8a 5c b5 00 41 8a d0 44 8a 54 b5 02 41 32 d3 8a c2 45 8a ca 44 32 4c b5 03 02 d2 c0 e8 07 41 8a d8 0f b6 c0 41 32 d9 6b c8 1b 41 32 db 32 ca 41 8a d0 41 32 cb 41 32 d2 32 cb 8a c2 88 4c b5 00 02 d2 c0 e8 07 0f b6 c0 6b c8 1b 41 8a c1 c0 e8 07 45 02 c9 0f b6 c0 32 ca 8a 54 b5 03 41 32 c8 41 32 d3 32 cb 88 4c b5 01 6b c8 1b 8a c2 c0 e8 07 02 d2 0f b6 c0 41 32 c9 41 32 ca 32 cb 88 4c b5 02 6b c8 1b 32 ca 32 4c b5 03 32 cb 88 4c b5 03 41 80 fd 04 0f 82 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_RevStealer_AR_2147977714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RevStealer.AR!MTB"
        threat_id = "2147977714"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RevStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b7 c0 48 8b 4c 24 08 48 69 c9 9b 45 00 00 0f b7 c9 03 c1 25 ff 00 00 00 88 44 24 02 48 8b 44 24 08 48 8b 4c 24 20 8a 04 01 88 44 24 01 8a 44 24 01 0f b6 c0 8a 4c 24 02 0f b6 c9 2b c1 88 04 24 8a 04 24 0f b6 c0 c1 f8 03 8a 0c 24 0f b6 c9 c1 e1 05 0b c1 48 8b 4c 24 08}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_RevStealer_AL_2147977744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RevStealer.AL!MTB"
        threat_id = "2147977744"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RevStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 c8 31 d2 45 0f b6 10 83 c1 01 41 f7 f3 49 83 c0 01 0f b6 04 16 44 01 d0 41 01 c1 41 0f b6 c1 0f b6 94 04 40 01 00 00 41 88 50 ff}  //weight: 2, accuracy: High
        $x_1_2 = {0f b6 ca 0f b6 84 0c 40 01 00 00 41 01 c0 45 0f b6 c8 46 0f b6 9c 0c 40 01 00 00 44 88 9c 0c 40 01 00 00 42 88 84 0c 40 01 00 00 02 84 0c 40 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

