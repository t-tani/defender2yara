rule Trojan_Win32_PShellDlr_SB_2147838602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PShellDlr.SB"
        threat_id = "2147838602"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PShellDlr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell" ascii //weight: 1
        $x_1_2 = "new-object net.webclient" ascii //weight: 1
        $x_1_3 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 68 00 74 00 74 00 70 00 [0-1] 3a 00 2f 00 2f 00 29 03 03 00 2e 00 29 03 03 00 2e 00 29 03 03 00 2e 00 29 03 03 00 3a 00 29 08 08 00 2f 00 31 20 20 00 2e 00 70 00 6e 00 67 00}  //weight: 1, accuracy: Low
        $x_1_4 = {6d 00 73 00 69 00 6d 00 61 00 6b 00 65 00 [0-16] 68 00 74 00 74 00 70 00 [0-1] 3a 00 2f 00 2f 00 29 03 03 00 2e 00 29 03 03 00 2e 00 29 03 03 00 2e 00 29 03 03 00 3a 00 29 08 08 00 2f 00 31 20 20 00 2e 00 70 00 6e 00 67 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PShellDlr_SA_2147848420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PShellDlr.SA"
        threat_id = "2147848420"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PShellDlr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell" ascii //weight: 1
        $x_1_2 = "new-object net.webclient" ascii //weight: 1
        $x_1_3 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 68 00 74 00 74 00 70 00 [0-1] 3a 00 2f 00 2f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

