rule Trojan_Win32_SuspTaskExec_YY_2147919557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspTaskExec.YY"
        threat_id = "2147919557"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspTaskExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "pythonw.exe" wide //weight: 1
        $x_1_2 = "taskhostw.exe" wide //weight: 1
        $x_100_3 = {20 00 2d 00 69 00 70 00 20 00 [0-255] 20 00 2d 00 70 00 6f 00 72 00 74 00 20 00 34 00 34 00 33 00}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

