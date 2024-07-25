rule Trojan_Win32_Badur_BD_2147752196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Badur.BD!MTB"
        threat_id = "2147752196"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Badur"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c4 08 8a 10 8b 44 24 18 8a 08 03 d1 81 e2 ff 00 00 80 79 08 4a 81 ca 00 ff ff ff 42 8b 44 24 20 81 e2 ff 00 00 00 8a 0c 32 8a 14 03 32 d1 88 14 03 8b 44 24 24 43 3b d8 0f}  //weight: 1, accuracy: High
        $x_1_2 = "\\shell\\open\\command" ascii //weight: 1
        $x_1_3 = "update.txt" ascii //weight: 1
        $x_1_4 = "\\SystemRoot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

