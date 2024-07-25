rule DoS_Win32_SharpWipe_B_2147849476_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win32/SharpWipe.B!dha"
        threat_id = "2147849476"
        type = "DoS"
        platform = "Win32: Windows 32-bit platform"
        family = "SharpWipe"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {20 00 2d 00 c7 45 ?? 61 00 63 00 c7 45 ?? 63 00 65 00 c7 45 ?? 70 00 74 00 c7 45 ?? 65 00 75 00 c7 45 ?? 6c 00 61 00 c7 45 ?? 20 00 2d 00}  //weight: 10, accuracy: Low
        $x_10_2 = {50 00 68 00 c7 45 ?? 79 00 73 00 c7 45 ?? 69 00 63 00 c7 45 ?? 61 00 6c 00 c7 45 ?? 44 00 72 00 c7 45 ?? 69 00 76 00 c7 45 ?? 65 00 25 00 c7 45 ?? 75 00 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

