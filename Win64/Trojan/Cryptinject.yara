rule Trojan_Win64_Cryptinject_QC_2147920337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cryptinject.QC!MTB"
        threat_id = "2147920337"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cryptinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\TEMP/qsxbkx.exe" ascii //weight: 1
        $x_1_2 = "rundll32.exe %s,rundll" ascii //weight: 1
        $x_1_3 = "powershell.exe -Command" ascii //weight: 1
        $x_1_4 = "gsjsoig.lnk" ascii //weight: 1
        $x_1_5 = "$WshShell.CreateShortcut($shortcutPath)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

