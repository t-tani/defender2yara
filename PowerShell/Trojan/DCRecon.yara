rule Trojan_PowerShell_DCRecon_A_2147782600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/DCRecon.A!ibt"
        threat_id = "2147782600"
        type = "Trojan"
        platform = "PowerShell: "
        family = "DCRecon"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 90 00 00 00}  //weight: 10, accuracy: High
        $x_5_2 = {5b 00 73 00 79 00 73 00 74 00 65 00 6d 00 2e 00 64 00 69 00 72 00 65 00 63 00 74 00 6f 00 72 00 79 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 2e 00 61 00 63 00 74 00 69 00 76 00 65 00 64 00 69 00 72 00 65 00 63 00 74 00 6f 00 72 00 79 00 2e 00 64 00 6f 00 6d 00 61 00 69 00 6e 00 5d 00 3a 00 3a 00 67 00 65 00 74 00 63 00 75 00 72 00 72 00 65 00 6e 00 74 00 64 00 6f 00 6d 00 61 00 69 00 6e 00 28 00 29 00 2e 00 64 00 6f 00 6d 00 61 00 69 00 6e 00 63 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 6c 00 65 00 72 00 73 00 90 00 00 00}  //weight: 5, accuracy: High
        $x_5_3 = {73 00 65 00 6c 00 65 00 63 00 74 00 2d 00 70 00 72 00 6f 00 70 00 65 00 72 00 74 00 79 00 6e 00 61 00 6d 00 65 00 2c 00 69 00 70 00 61 00 64 00 64 00 72 00 65 00 73 00 73 00 2c 00 6f 00 73 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 90 00 00 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

