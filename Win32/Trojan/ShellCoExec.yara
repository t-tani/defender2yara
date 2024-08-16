rule Trojan_Win32_ShellCoExec_C_2147918848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShellCoExec.C!MTB"
        threat_id = "2147918848"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellCoExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 63 d8 41 8b c0 f7 e9 d1 fa 8b c2 c1 e8 1f 03 d0 41 8b c0 f7 ea d1 fa 8b c2 c1 e8 1f 03 d0 41 8b c0 f7 ea d1 fa 8b c2 c1 e8 1f 03 d0 41 8b c0 f7 ea 41 8b c0 d1 fa 8b ca}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

