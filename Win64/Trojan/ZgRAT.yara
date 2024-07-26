rule Trojan_Win64_ZgRAT_A_2147899811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZgRAT.A!MTB"
        threat_id = "2147899811"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 00 83 f8 ff 74 ?? a8 10 75 ?? 48 8d 0d ?? ?? ?? 00 ff 15 ?? ?? 02 00 83 f8 ff 74 ?? a8 10 75 ?? 48 8d 0d ?? ?? ?? 00 ff 15 ?? ?? 02 00 83 f8 ff 0f 84 ?? ?? 00 00 a8 10 0f 84}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

