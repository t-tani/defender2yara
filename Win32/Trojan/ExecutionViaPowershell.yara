rule Trojan_Win32_ExecutionViaPowershell_A_2147919725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ExecutionViaPowershell.A"
        threat_id = "2147919725"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ExecutionViaPowershell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set-MpPreference" wide //weight: 1
        $x_1_2 = "Get-MpPreference" wide //weight: 1
        $x_1_3 = "Get-MpComputerStatus" wide //weight: 1
        $x_1_4 = "Get-Process" wide //weight: 1
        $x_6_5 = "powershell" wide //weight: 6
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

