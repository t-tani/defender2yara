rule Trojan_Win32_AdfindRecon_C_2147782851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AdfindRecon.C!ibt"
        threat_id = "2147782851"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AdfindRecon"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 61 00 64 00 66 00 69 00 6e 00 64 00 2e 00 65 00 78 00 65 00 90 00 00 00}  //weight: 10, accuracy: High
        $x_5_2 = {2d 00 66 00 20 00 6f 00 62 00 6a 00 65 00 63 00 74 00 63 00 61 00 74 00 65 00 67 00 6f 00 72 00 79 00 3d 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 20 00 2d 00 63 00 73 00 76 00 20 00 6e 00 61 00 6d 00 65 00 20 00 63 00 6e 00 20 00 6f 00 70 00 65 00 72 00 61 00 74 00 69 00 6e 00 67 00 73 00 79 00 73 00 74 00 65 00 6d 00 20 00 64 00 6e 00 73 00 68 00 6f 00 73 00 74 00 6e 00 61 00 6d 00 65 00 90 00 00 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

