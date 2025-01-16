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

rule Trojan_Win64_Cryptinject_YBA_2147930737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cryptinject.YBA!MTB"
        threat_id = "2147930737"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cryptinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_11_1 = {33 45 df 21 c2 8a 55 ec 48 03 5d e8 03 5d c4 48 8b 45 ac 0f b7 d2}  //weight: 11, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

