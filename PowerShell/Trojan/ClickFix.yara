rule Trojan_PowerShell_ClickFix_AB_2147948541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/ClickFix.AB!MTB"
        threat_id = "2147948541"
        type = "Trojan"
        platform = "PowerShell: "
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "invoke-webrequest" wide //weight: 1
        $x_1_2 = "iwr" wide //weight: 1
        $x_1_3 = "-useb" wide //weight: 1
        $x_10_4 = ".com/run/" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_PowerShell_ClickFix_SVI_2147977853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/ClickFix.SVI"
        threat_id = "2147977853"
        type = "Trojan"
        platform = "PowerShell: "
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_10_2 = "[scriptblock]::create((" wide //weight: 10
        $x_10_3 = "curl.exe" wide //weight: 10
        $x_10_4 = "--insecure -s" wide //weight: 10
        $x_10_5 = "http" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_PowerShell_ClickFix_SVJ_2147977854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/ClickFix.SVJ"
        threat_id = "2147977854"
        type = "Trojan"
        platform = "PowerShell: "
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "[powershell]::create()" wide //weight: 10
        $x_10_2 = ".addscript((curl.exe" wide //weight: 10
        $x_10_3 = "--insecure -s" wide //weight: 10
        $x_10_4 = ".invoke()" wide //weight: 10
        $x_10_5 = "http" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

