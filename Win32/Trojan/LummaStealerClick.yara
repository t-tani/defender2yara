rule Trojan_Win32_LummaStealerClick_A_2147931073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealerClick.A!MTB"
        threat_id = "2147931073"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealerClick"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "-split ($" wide //weight: 1
        $x_1_3 = ".CreateDecryptor(" wide //weight: 1
        $x_1_4 = "-replace" wide //weight: 1
        $x_1_5 = ".Substring(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealerClick_B_2147931148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealerClick.B!MTB"
        threat_id = "2147931148"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealerClick"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "$env:computername" wide //weight: 1
        $x_1_3 = "iex $" wide //weight: 1
        $x_1_4 = "useragent" wide //weight: 1
        $x_1_5 = ".php?compname" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealerClick_D_2147931675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealerClick.D!MTB"
        threat_id = "2147931675"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealerClick"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "[system.io.file]::create($" wide //weight: 10
        $x_10_2 = "http" wide //weight: 10
        $x_10_3 = "$env:computername" wide //weight: 10
        $x_1_4 = "invoke-webrequest $" wide //weight: 1
        $x_1_5 = "iwr $" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_LummaStealerClick_I_2147932422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealerClick.I"
        threat_id = "2147932422"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealerClick"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 00 74 00 74 00 70 00 [0-60] 7c 00 20 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 20 00 2d 00}  //weight: 10, accuracy: Low
        $x_10_2 = "iex" wide //weight: 10
        $x_1_3 = "mshta" wide //weight: 1
        $x_1_4 = "m*ta.e" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_LummaStealerClick_K_2147932423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealerClick.K"
        threat_id = "2147932423"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealerClick"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "hidden" wide //weight: 1
        $x_1_3 = "iwr http" wide //weight: 1
        $x_1_4 = ".ps1 | iex" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

