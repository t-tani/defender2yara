rule Trojan_Win32_ParallaxRat_CCEE_2147896974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ParallaxRat.CCEE!MTB"
        threat_id = "2147896974"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ParallaxRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe c3 8a 94 1d ?? ?? ?? ?? 02 c2 8a 8c 05 ?? ?? ?? ?? 88 8c 1d}  //weight: 1, accuracy: Low
        $x_1_2 = {30 0e 46 4f 0f 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

