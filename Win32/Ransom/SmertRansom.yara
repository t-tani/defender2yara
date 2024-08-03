rule Ransom_Win32_SmertRansom_YAF_2147917647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/SmertRansom.YAF!MTB"
        threat_id = "2147917647"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "SmertRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "--food" ascii //weight: 1
        $x_1_2 = ".smert" ascii //weight: 1
        $x_1_3 = "\\README.txt" ascii //weight: 1
        $x_1_4 = "you got fucked" ascii //weight: 1
        $x_1_5 = "no way to recover the files" ascii //weight: 1
        $x_1_6 = "wuauserv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

