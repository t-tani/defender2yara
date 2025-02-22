rule Trojan_PowerShell_LummaStealer_B_2147934184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/LummaStealer.B"
        threat_id = "2147934184"
        type = "Trojan"
        platform = "PowerShell: "
        family = "LummaStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "*g'}).Name)" wide //weight: 1
        $x_1_2 = ").Value.((" wide //weight: 1
        $x_1_3 = "(GI Variable:" wide //weight: 1
        $x_1_4 = "_.Name" wide //weight: 1
        $x_1_5 = "|GM" wide //weight: 1
        $x_1_6 = "SI" wide //weight: 1
        $x_1_7 = "Net.WebClient" wide //weight: 1
        $x_1_8 = "powershell.exe" wide //weight: 1
        $x_1_9 = "Command" wide //weight: 1
        $x_1_10 = ".Invoke" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

