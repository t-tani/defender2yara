rule VirTool_Win32_SuspNetbiosShell_A_2147977689_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspNetbiosShell.A"
        threat_id = "2147977689"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspNetbiosShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "7QZjAXP0A0AkAAQ2AB2BB0BBABXP8ABu" ascii //weight: 1
        $x_1_2 = {5d 8b 45 00 b9 ?? ?? ?? ?? 83 c5 01 39 c8 75 f1 83 c5 03 55 31 f6 31 ff 31 db 66 8b 5c 35 00 b9 61 61 00 00 39 cb 74 23 31 c0 31 d2 88 da 80 ea 41 89 d0 c1 e0 04 31 d2 88 fa 80 ea 41 01 d0 88 44 3d 00 83 c7 01 83 c6 02 eb cd 58 ff e0 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

