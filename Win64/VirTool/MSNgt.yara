rule VirTool_Win64_MSNgt_A_2147977660_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/MSNgt.A"
        threat_id = "2147977660"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "MSNgt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 89 64 24 30 ?? ?? ?? ?? ?? ?? ?? c7 44 24 28 00 00 00 02 45 33 c9 ba 00 00 00 80 c7 44 24 20 03 00 00 00 41 b8 07 00 00 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 89 64 24 78 41 b9 19 00 02 00 48 89 44 24 20 45 33 c0 ?? ?? ?? ?? ?? ?? ?? 48 c7 c1 02 00 00 80 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

