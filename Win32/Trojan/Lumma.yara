rule Trojan_Win32_Lumma_RDA_2147891693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lumma.RDA!MTB"
        threat_id = "2147891693"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lumma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 c8 31 d2 f7 f6 0f b6 44 0d 00 32 04 17 88 44 0d 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lumma_RZ_2147912859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lumma.RZ!MTB"
        threat_id = "2147912859"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lumma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {04 4e 34 70 2c 65 34 22 2c 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

