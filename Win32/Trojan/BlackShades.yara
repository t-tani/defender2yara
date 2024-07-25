rule Trojan_Win32_BlackShades_MA_2147844557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackShades.MA!MTB"
        threat_id = "2147844557"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackShades"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {f2 17 4d 96 ab ef 86 81 3d 67 66}  //weight: 5, accuracy: High
        $x_3_2 = {40 7e 7e 40 4d 69 63 72 6f 73 6f 66 74 40 7e 7e 40 33 40 7e 7e 40 7c 4f 4e 7c 40 7e 7e 40 0d 0a}  //weight: 3, accuracy: High
        $x_3_3 = {f6 0c 38 73 37 0d 38 73 68 3b 3a 73 e4 d8 37 73 a3 6d 38 73 fa 98 36 73 c6 5a 37 73 f2 a0 2a 73 0d 99 36 73 0b 98 36 73 54 45 38 73 4b 7b 39 73}  //weight: 3, accuracy: High
        $x_3_4 = "jkbviep" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackShades_MBZW_2147907476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackShades.MBZW!MTB"
        threat_id = "2147907476"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackShades"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {42 00 d0 30 42 00 b8 31 42 00 f0 2a 42 00}  //weight: 1, accuracy: High
        $x_1_2 = {2b 40 00 a4 12 40 00 40 f0 34 00 00 ff ff ff 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

