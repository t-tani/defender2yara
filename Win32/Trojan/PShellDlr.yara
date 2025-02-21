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
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_10_2 = {6e 00 65 00 77 00 2d 00 6f 00 62 00 6a 00 65 00 63 00 74 00 [0-32] 6e 00 65 00 74 00 2e 00 77 00 65 00 62 00 63 00 6c 00 69 00 65 00 6e 00 74 00}  //weight: 10, accuracy: Low
        $x_1_3 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-48] 2e 00 73 00 68 00 6f 00 70 00}  //weight: 1, accuracy: Low
        $x_1_4 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-48] 2e 00 78 00 79 00 7a 00}  //weight: 1, accuracy: Low
        $x_1_5 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-48] 2e 00 62 00 69 00 7a 00}  //weight: 1, accuracy: Low
        $x_1_6 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-48] 2e 00 63 00 79 00 6f 00 75 00}  //weight: 1, accuracy: Low
        $x_1_7 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-48] 2e 00 63 00 6c 00 69 00 63 00 6b 00}  //weight: 1, accuracy: Low
        $x_1_8 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-48] 2e 00 6c 00 61 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_PShellDlr_SB_2147838602_1
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

rule Trojan_Win32_PShellDlr_SC_2147931676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PShellDlr.SC"
        threat_id = "2147931676"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PShellDlr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_10_2 = "net.webclient" wide //weight: 10
        $x_10_3 = ").invoke(" wide //weight: 10
        $x_10_4 = ").value|foreach" wide //weight: 10
        $x_1_5 = {68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-48] 2e 00 73 00 68 00 6f 00 70 00}  //weight: 1, accuracy: Low
        $x_1_6 = {68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-48] 2e 00 78 00 79 00 7a 00}  //weight: 1, accuracy: Low
        $x_1_7 = {68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-48] 2e 00 62 00 69 00 7a 00}  //weight: 1, accuracy: Low
        $x_1_8 = {68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-48] 2e 00 63 00 79 00 6f 00 75 00}  //weight: 1, accuracy: Low
        $x_1_9 = {68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-48] 2e 00 63 00 6c 00 69 00 63 00 6b 00}  //weight: 1, accuracy: Low
        $x_1_10 = {68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-48] 2e 00 6c 00 61 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_PShellDlr_PA_2147934093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PShellDlr.PA!MTB"
        threat_id = "2147934093"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PShellDlr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "New-NetFirewallRule -DisplayName" wide //weight: 1
        $x_1_3 = "Windows Update" wide //weight: 1
        $x_2_4 = {2d 00 52 00 65 00 6d 00 6f 00 74 00 65 00 41 00 64 00 64 00 72 00 65 00 73 00 73 00 20 00 [0-48] 20 00 2d 00 50 00 72 00 6f 00 74 00 6f 00 63 00 6f 00 6c 00 20 00 54 00 43 00 50 00 20 00 2d 00 41 00 63 00 74 00 69 00 6f 00 6e 00 20 00 41 00 6c 00 6c 00 6f 00 77 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

