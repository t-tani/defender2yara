rule VirTool_Win32_MSNgt_B_2147977661_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/MSNgt.B"
        threat_id = "2147977661"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "MSNgt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 68 03 00 1f 00 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {50 57 ff 15 ?? ?? ?? ?? 68 e8 03 00 00 ff 15 ?? ?? ?? ?? 6a 00 6a 02 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

