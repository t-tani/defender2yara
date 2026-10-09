rule Trojan_Win64_Cornflake_CF_2147980029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cornflake.CF!MTB"
        threat_id = "2147980029"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cornflake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 39 ca 73 ?? 49 89 d2 41 83 e2 ?? 47 8a 54 02 ?? 45 32 14 11 44 88 14 10 48 ff c2 eb}  //weight: 3, accuracy: Low
        $x_5_2 = {89 c2 83 e2 ?? 8d 6a ?? 41 89 d1 41 8a 14 03 42 32 54 0c ?? 32 14 2b 41 88 14 03 48 ff c0 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

