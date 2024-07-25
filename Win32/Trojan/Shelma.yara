rule Trojan_Win32_Shelma_RPY_2147824775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shelma.RPY!MTB"
        threat_id = "2147824775"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shelma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b d1 83 e2 03 8a 54 02 08 32 54 08 14 88 14 31 41 81 f9 0e 01 00 00 76 e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Shelma_NS_2147901793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shelma.NS!MTB"
        threat_id = "2147901793"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shelma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WinExec" ascii //weight: 1
        $x_1_2 = "/cv/efryes.exe" wide //weight: 1
        $x_1_3 = "sdfer.exe" wide //weight: 1
        $x_1_4 = "uuu.run.place" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

