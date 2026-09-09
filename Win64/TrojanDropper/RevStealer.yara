rule TrojanDropper_Win64_RevStealer_CH_2147977749_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/RevStealer.CH!MTB"
        threat_id = "2147977749"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "RevStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 f0 48 8b 44 24 ?? 31 30 48 83 c3 04 48 8b 44 24 ?? 48 83 c0 04 48 89 44 24 ?? 48 8b 44 24 ?? 48 3b d8 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

