rule Trojan_Win32_ModifyFileAssociation_A_2147925448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ModifyFileAssociation.A"
        threat_id = "2147925448"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ModifyFileAssociation"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 00 63 00 20 00 [0-2] 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 [0-32] 5c 00 63 00 68 00 61 00 6e 00 67 00 65 00 5f 00 64 00 65 00 66 00 61 00 75 00 6c 00 74 00 5f 00 66 00 69 00 6c 00 65 00 5f 00 61 00 73 00 73 00 6f 00 63 00 69 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 62 00 61 00 74 00}  //weight: 1, accuracy: Low
        $x_1_2 = "/c ftype txtfile" wide //weight: 1
        $x_3_3 = ":\\windows\\system32\\cmd.exe" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

