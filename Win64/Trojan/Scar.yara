rule Trojan_Win64_Scar_GMK_2147892258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Scar.GMK!MTB"
        threat_id = "2147892258"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Scar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {4c 89 f1 4c 89 4c 24 58 e8 ?? ?? ?? ?? 31 d2 41 ba 3e 00 00 00 44 89 f9 89 c0 41 ff c7 4c 8b 4c 24 58 49 f7 f2 44 39 7c 24 48 66 0f be 44 15 00 66 41 89 04 4c}  //weight: 10, accuracy: Low
        $x_1_2 = "Global\\M%llu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

