rule Trojan_Win32_NjRAT_A_2147917650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NjRAT.A!MTB"
        threat_id = "2147917650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {f5 00 00 00 00 f5 80 00 00 00 6c 0c 00 4d 50 ff 08 40 04 ?? ff 0a 00 00 10 00 04 ?? ff fc 60 3c}  //weight: 4, accuracy: Low
        $x_2_2 = {f5 00 00 00 00 f5 ff ff ff ff f5 01 00 00 00 f5 00 00 00 00 1b 04 00 80 0c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

