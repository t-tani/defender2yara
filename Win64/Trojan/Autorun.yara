rule Trojan_Win64_Autorun_MP_2147908913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Autorun.MP!MTB"
        threat_id = "2147908913"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Autorun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 06 83 f8 01 0f 84 4c 01 00 00 85 ff 0f 84 65 01 00 00 48 8b 05 51 27 1c 00 48 8b 00 48 85 c0 74 0c 45 31 c0 ba 02 00 00 00 31 c9}  //weight: 1, accuracy: High
        $x_1_2 = {75 e3 48 8b 35 8c 28 1c 00 31 ff 8b 06 83 f8 01 0f 84 56 01 00 00 8b 06 85 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

