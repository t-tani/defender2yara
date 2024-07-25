rule Trojan_Win32_AccessibilityEscalation_GR_2147755306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AccessibilityEscalation.GR!MSR"
        threat_id = "2147755306"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AccessibilityEscalation"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/v ShowSuperHidden /t REG_DWORD /d 0 /f" ascii //weight: 1
        $x_2_2 = "Image File Execution Options\\sethc.exe\" /v Debugger /t REG_SZ /d \"C:\\windows\\system32\\taskmgr.exe\" /f" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

