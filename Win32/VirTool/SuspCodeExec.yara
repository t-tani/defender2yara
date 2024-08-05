rule VirTool_Win32_SuspCodeExec_A_2147917847_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspCodeExec.A"
        threat_id = "2147917847"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspCodeExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "csc.exe" ascii //weight: 1
        $x_1_2 = {2f 00 6f 00 75 00 74 00 3a 00 63 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 [0-48] 2e 00 65 00 78 00 65 00 [0-8] 63 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 [0-80] 2e 00 63 00 73 00}  //weight: 1, accuracy: Low
        $x_1_3 = {2f 6f 75 74 3a 63 3a 5c 77 69 6e 64 6f 77 73 5c 74 65 6d 70 5c [0-48] 2e 65 78 65 [0-8] 63 3a 5c 77 69 6e 64 6f 77 73 5c 74 65 6d 70 5c [0-80] 2e 63 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

