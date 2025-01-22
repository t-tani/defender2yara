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

