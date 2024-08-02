rule Ransom_Win32_Embargo_DA_2147912233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Embargo.DA!MTB"
        threat_id = "2147912233"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Embargo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 00 6d 00 62 00 61 00 72 00 67 00 6f 00 3a 00 3a 00 [0-15] 3a 00 3a 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00}  //weight: 1, accuracy: Low
        $x_1_2 = {65 6d 62 61 72 67 6f 3a 3a [0-15] 3a 3a 65 6e 63 72 79 70 74}  //weight: 1, accuracy: Low
        $x_1_3 = "C:\\Windows\\System32\\cmd.exe/q/cbcdedit/set{default}recoveryenabledno" ascii //weight: 1
        $x_1_4 = "Deleted  shadows" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

