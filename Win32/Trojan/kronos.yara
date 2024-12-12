rule Trojan_Win32_kronos_BKL_2147928099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/kronos.BKL!MTB"
        threat_id = "2147928099"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "kronos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 a1 30 00 00 00 8b 40 0c 8b 40 0c 8b 40 18 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

