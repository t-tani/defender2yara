rule Trojan_Win32_SnakeKeylogger_VX_2147793434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SnakeKeylogger.VX!MTB"
        threat_id = "2147793434"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 a8 8b 4d bc 8b 55 ac 83 7d c4 00 0f 95 c3 80 f3 ff 80 e3 01 0f b6 f3 89 34 24 89 54 24 04 89 4c 24 08 89 44 24 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SnakeKeylogger_AB_2147796807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SnakeKeylogger.AB!MTB"
        threat_id = "2147796807"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 a0 99 b9 03 00 00 00 f7 f9 8b 85 18 f8 ff ff 0f be 0c 10 8b 55 a0 0f b6 44 15 a4 33 c1 8b 4d a0 88 44 0d a4 eb c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SnakeKeylogger_RPY_2147845778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SnakeKeylogger.RPY!MTB"
        threat_id = "2147845778"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f6 d0 04 52 34 7f 2a c1 f6 d0 04 5e f6 d0 32 c1 c0 c0 02 f6 d8 88 81 ?? ?? ?? ?? 41 81 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SnakeKeylogger_MBXZ_2147925618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SnakeKeylogger.MBXZ!MTB"
        threat_id = "2147925618"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 06 07 28 ?? ?? ?? 06 0c 04 03 6f ?? ?? ?? 0a 59 0d 03 08 09 28 ?? ?? ?? 06 00 07 17 58 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

