rule Trojan_Win32_BSStealer_A_2147898743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BSStealer.A!MTB"
        threat_id = "2147898743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BSStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f be c0 33 c3 69 d8 ?? ?? ?? ?? 8a 01 41 84 c0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

