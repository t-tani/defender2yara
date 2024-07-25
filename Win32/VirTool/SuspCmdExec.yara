rule VirTool_Win32_SuspCmdExec_A_2147915743_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspCmdExec.A"
        threat_id = "2147915743"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspCmdExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cmd.exe /c" ascii //weight: 1
        $x_1_2 = {5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 54 00 45 00 4d 00 50 00 5c 00 [0-32] 5c 00 [0-96] 2e 00 62 00 61 00 74 00}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 57 69 6e 64 6f 77 73 5c 54 45 4d 50 5c [0-32] 5c [0-96] 2e 62 61 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

