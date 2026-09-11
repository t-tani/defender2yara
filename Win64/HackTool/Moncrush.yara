rule HackTool_Win64_Moncrush_VA_2147978096_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Moncrush.VA!MTB"
        threat_id = "2147978096"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Moncrush"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "delete self after succes" ascii //weight: 1
        $x_1_2 = "enumerate targets without killing" ascii //weight: 1
        $x_1_3 = "MonProcessEX.sys" ascii //weight: 1
        $x_1_4 = "EDR process terminator" ascii //weight: 1
        $x_1_5 = "moncrush.pdb" ascii //weight: 1
        $x_1_6 = "\\\\.\\MonProcessEX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

