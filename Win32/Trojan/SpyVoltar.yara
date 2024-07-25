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

