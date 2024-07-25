rule Trojan_Win64_MysticStealer_YAA_2147900612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MysticStealer.YAA!MTB"
        threat_id = "2147900612"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MysticStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 89 c9 ff c1 41 0f af c9 f6 c1 01 41 0f 94 c1 44 30 ca 84 d2 41 b9 a8 08 00 00 ba ?? ?? ?? ?? 49 0f 45 d1 f6 c1 01 48 89 d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

