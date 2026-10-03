rule TrojanDropper_Win64_Xegumumune_C_2147979699_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/Xegumumune.C!MTB"
        threat_id = "2147979699"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "Xegumumune"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {48 8d 4c 24 ?? 49 03 c8 49 ff c0 8a 04 0a 34 ?? 88 01 4d 3b c1 7c}  //weight: 15, accuracy: Low
        $x_15_2 = {48 8b c1 4c 8d 05 ?? ?? ?? ?? 83 e0 ?? 42 8a 04 00 30 04 0e 48 ff c1 48 3b ca 72}  //weight: 15, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

