rule Trojan_Win32_SuspPosLoadz_ZH_2147979860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspPosLoadz.ZH!MTB"
        threat_id = "2147979860"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspPosLoadz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "'M*.*er*.*t*y'" wide //weight: 1
        $x_1_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-60] 24 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspPosLoadz_ZG_2147979966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspPosLoadz.ZG!MTB"
        threat_id = "2147979966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspPosLoadz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[scriptblock]::Create([IO.File]::ReadAllText(" wide //weight: 1
        $x_1_2 = ".ps1')).Invoke()" wide //weight: 1
        $x_1_3 = "appdata" wide //weight: 1
        $x_1_4 = "hidden" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspPosLoadz_ZI_2147979967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspPosLoadz.ZI!MTB"
        threat_id = "2147979967"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspPosLoadz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Get-Random" wide //weight: 1
        $x_1_2 = "[char]$_" wide //weight: 1
        $x_1_3 = "WebClient" wide //weight: 1
        $x_1_4 = "$env:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

