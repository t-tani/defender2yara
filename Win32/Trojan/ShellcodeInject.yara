rule Trojan_Win32_ShellcodeInject_ZX_2147914001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShellcodeInject.ZX!MTB"
        threat_id = "2147914001"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellcodeInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 34 18 2d 40 3b c7 72 f7 60 ff 95 8c fd ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

