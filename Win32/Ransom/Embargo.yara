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
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "embargo::crypter::encrypt" ascii //weight: 1
        $x_1_2 = "C:\\Windows\\System32\\cmd.exe/q/cbcdedit/set{default}recoveryenabledno" ascii //weight: 1
        $x_1_3 = "Finish encrypted" ascii //weight: 1
        $x_1_4 = "Deleted  shadows" ascii //weight: 1
        $x_1_5 = "Wow64DisableWow64FsRedirection" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

