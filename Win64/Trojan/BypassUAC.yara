rule Trojan_Win64_BypassUAC_NE_2147920713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BypassUAC.NE!MTB"
        threat_id = "2147920713"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BypassUAC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "System\\CurrentControlSet\\Control\\Nls\\Calendars\\Japanese\\Era" ascii //weight: 2
        $x_2_2 = "C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\powershell.ex" ascii //weight: 2
        $x_2_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Ru" ascii //weight: 2
        $x_1_4 = "C:\\windows\\tem" ascii //weight: 1
        $x_1_5 = "$disable uac" ascii //weight: 1
        $x_1_6 = "$disable regedit" ascii //weight: 1
        $x_1_7 = "hentai" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

