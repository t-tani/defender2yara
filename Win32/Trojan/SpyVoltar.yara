rule Trojan_Win32_SpyVoltar_PACN_2147900456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyVoltar.PACN!MTB"
        threat_id = "2147900456"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyVoltar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 d0 29 d0 b9 0a 00 00 00 31 db 31 d2 f7 f1 83 c2 30 88 14 1c 43 85 c0 75 f1}  //weight: 1, accuracy: High
        $x_1_2 = {68 bd 01 00 00 68 bd 01 00 00 6a 22 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyVoltar_ASV_2147916951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyVoltar.ASV!MTB"
        threat_id = "2147916951"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyVoltar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 71 ff 8a 11 66 33 54 45 84 66 c1 c2 08 66 89 14 47 40 3b c6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

