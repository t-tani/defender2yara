rule Trojan_Win32_Virut_AVI_2147907810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Virut.AVI!MTB"
        threat_id = "2147907810"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Virut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 b7 6f c5 20 ba 2b e1 8d 1b fa 85 ee 1f 53 ef 34 a2 cf 56}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

