rule Trojan_Win64_Zenpak_GXM_2147918428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zenpak.GXM!MTB"
        threat_id = "2147918428"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 f7 e1 48 c1 ea ?? 48 69 d2 ?? ?? ?? ?? 48 2b ca 42 8a 04 11 41 30 01 49 ff c1 41 81 f8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

