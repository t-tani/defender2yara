rule Trojan_Win32_DefEva_A_2147977833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DefEva.A!MTB"
        threat_id = "2147977833"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DefEva"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "root\\SecurityCenter2" wide //weight: 1
        $x_1_2 = "AntiVirusProduct" wide //weight: 1
        $x_1_3 = "Get-WmiObject" wide //weight: 1
        $x_1_4 = "displayName -replace 'Windows Defender'" wide //weight: 1
        $x_1_5 = "ComputerName $env:computername" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

