rule Trojan_Win64_VibrantPony_A_2147919754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VibrantPony.A!dha"
        threat_id = "2147919754"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VibrantPony"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 bc 00 30 00 00 41 b9 04 00 00 00 ba 00 28 00 00 33 c9 45 8b c4 48 89 45 ?? ff d7}  //weight: 5, accuracy: Low
        $x_5_2 = {49 63 46 3c 44 0f be 4d af 45 8b c4 42 8b 54 30 50 41 c1 e1 03 33 c9 ff d7}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

