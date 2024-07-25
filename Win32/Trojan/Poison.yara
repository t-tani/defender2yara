rule Trojan_Win32_Poison_RPS_2147835817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Poison.RPS!MTB"
        threat_id = "2147835817"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d d0 83 c1 01 89 4d d0 83 7d d0 0d 73 17 8b 55 d0 33 c0 8a 44 15 e0 35 cc 00 00 00 8b 4d d0 88 44 0d e0 eb da}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Poison_EM_2147850225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Poison.EM!MTB"
        threat_id = "2147850225"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EZEL\\newsletter\\VB6" ascii //weight: 1
        $x_1_2 = "Hiccupp2" ascii //weight: 1
        $x_1_3 = "frump6" ascii //weight: 1
        $x_1_4 = "nslt.pdf" wide //weight: 1
        $x_1_5 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

