rule Trojan_Win32_Mimikatz_BL_2147836632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mimikatz.BL!MTB"
        threat_id = "2147836632"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 04 39 84 c0 74 09 3c be 74 05 34 be 88 04 39 41 3b ce 72}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mimikatz_RPX_2147837580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mimikatz.RPX!MTB"
        threat_id = "2147837580"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "updates.microsoftupdatesoftware.ga" wide //weight: 1
        $x_1_2 = "picturess/Class.dll" wide //weight: 1
        $x_1_3 = "87.251.log" ascii //weight: 1
        $x_1_4 = "urlmon.dll" ascii //weight: 1
        $x_1_5 = "EnableWindow" ascii //weight: 1
        $x_1_6 = "URLOpenBlockingStreamW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mimikatz_ASJ_2147923183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mimikatz.ASJ!MTB"
        threat_id = "2147923183"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {fe c3 8a 14 1f 00 d0 8a 0c 07 88 0c 1f 88 14 07 00 d1 8a 0c 0f 30 0e 46 ff 4d 14 75}  //weight: 5, accuracy: High
        $x_1_2 = {89 e5 6a 04 68 00 30 00 00 68 00 00 e0 06 6a 00 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {f7 e2 3c 61 72 04 3c 7a 76 0d 2d 21 30 00 00 81 c2 21 30 00 00 eb e9 aa e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

