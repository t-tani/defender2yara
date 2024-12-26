rule Trojan_Win32_ValleyRat_AVA_2147929127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRat.AVA!MTB"
        threat_id = "2147929127"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {53 56 57 6a 00 6a 00 68 04 01 00 00 8d 44 24 24 8b f9 50 68 b0 53 40 00 89 7c 24 24 6a 00 89 7c 24 28 ff 15}  //weight: 2, accuracy: High
        $x_1_2 = {2b 45 e0 6a 40 68 00 30 00 00 50 6a 00 ff 15 ?? ?? ?? ?? 8b f0 85 f6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

