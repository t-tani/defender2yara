rule Ransom_Win32_GenRan_SA_2147917264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GenRan.SA"
        threat_id = "2147917264"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GenRan"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 5c 00 6c 00 6f 00 63 00 61 00 6c 00 5c 00 [0-8] 2d 00 [0-4] 2d 00 [0-4] 2d 00 [0-4] 2d 00 [0-12] 5c 00 [0-8] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = "--Task" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

