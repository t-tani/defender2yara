rule Trojan_Win32_Strictor_GMR_2147893059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strictor.GMR!MTB"
        threat_id = "2147893059"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strictor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".vmp0" ascii //weight: 1
        $x_1_2 = "PFGydcB" ascii //weight: 1
        $x_1_3 = "Logon.exe" ascii //weight: 1
        $x_1_4 = "rxjhdlq.bak" ascii //weight: 1
        $x_1_5 = "XWuiqx" ascii //weight: 1
        $x_1_6 = "iwvRMHx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

