rule Trojan_PowerShell_FuzzedTank_B_2147977900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/FuzzedTank.B!dha"
        threat_id = "2147977900"
        type = "Trojan"
        platform = "PowerShell: "
        family = "FuzzedTank"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-file C:\\Windows\\System32\\ext.ps1 https:" wide //weight: 1
        $x_1_2 = "-UserAgent 'teamsdk' -UseBasicParsing" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

