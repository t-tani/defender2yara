rule Trojan_Win64_XWorm_GPA_2147904521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.GPA!MTB"
        threat_id = "2147904521"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "src\\main.rshttps://107.175.3.10" ascii //weight: 5
        $x_5_2 = ".binhttps://github.comInternet" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_DA_2147922667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.DA!MTB"
        threat_id = "2147922667"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:/explorerwin/mewobfm.dll" ascii //weight: 1
        $x_1_2 = "Failed to load the DLL" ascii //weight: 1
        $x_10_3 = "C:/explorerwi/explorer.exe" ascii //weight: 10
        $x_1_4 = "C:/explorerwin/python.exe" ascii //weight: 1
        $x_12_5 = "C:/explorerwi/pdf.dll" ascii //weight: 12
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((1 of ($x_12_*) and 1 of ($x_1_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

