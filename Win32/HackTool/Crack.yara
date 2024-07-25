rule HackTool_Win32_Crack_2147745913_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Crack!MTB"
        threat_id = "2147745913"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Crack"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cracker" ascii //weight: 1
        $x_1_2 = "*START PATCHING*" ascii //weight: 1
        $x_1_3 = "OFFSET PATCH" ascii //weight: 1
        $x_1_4 = "SEARCH & REPLACE PATCH" ascii //weight: 1
        $x_1_5 = "PATCHING DONE" ascii //weight: 1
        $x_1_6 = "Patchtarget" ascii //weight: 1
        $x_1_7 = "REGISTRY PATCH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Crack_2147745913_1
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Crack!MTB"
        threat_id = "2147745913"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Crack"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "repacks.ddns.net" ascii //weight: 1
        $x_1_2 = "s:\\IDM_projects\\IDMIECC2\\64bit\\ReleaseMinDependency\\IDMIECC64.pdb" ascii //weight: 1
        $x_1_3 = "Activate.cmd" ascii //weight: 1
        $x_1_4 = "PureFlat.tbi" ascii //weight: 1
        $x_1_5 = "Tonek Inc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

