rule Trojan_Win64_AsyncRat_RPX_2147902277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AsyncRat.RPX!MTB"
        threat_id = "2147902277"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 b9 40 00 00 00 31 c9 41 b8 00 10 00 00 ba d3 ca 00 00 ff 10 b9 d0 07 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AsyncRat_RPY_2147902278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AsyncRat.RPY!MTB"
        threat_id = "2147902278"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c2 c1 c9 08 41 03 c8 8b d3 41 33 c9 c1 ca 08 41 03 d1 41 c1 c0 03 41 33 d2 41 c1 c1 03 44 33 ca 44 33 c1 41 ff c2 41 8b db 44 8b d8 41 83 fa 1b 72 cd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AsyncRat_CCHU_2147903527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AsyncRat.CCHU!MTB"
        threat_id = "2147903527"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8d 8c 24 60 02 00 00 4c 8d 84 24 30 02 00 00 48 8d 15 ?? ?? 01 00 48 8d 0d ?? ?? 01 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AsyncRat_ASC_2147922422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AsyncRat.ASC!MTB"
        threat_id = "2147922422"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 83 ec 28 48 8d 15 f5 44 00 00 48 8d 0d f6 78 00 00 e8 ?? ?? ?? ?? 48 8d 0d 32 34 00 00 48 83 c4 28}  //weight: 5, accuracy: Low
        $x_2_2 = "seftali\\x64\\Release\\seftali.pdb" ascii //weight: 2
        $x_3_3 = "https://github.com/errias/XWorm-Rat-Remote-Administration-Tool-/raw/main/XWormUI.exe" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

