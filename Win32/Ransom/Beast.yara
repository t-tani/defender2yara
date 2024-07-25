rule Ransom_Win32_Beast_YAA_2147907041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Beast.YAA!MTB"
        threat_id = "2147907041"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Beast"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 74 04 0c 55 40 83 f8 0b 72 f5}  //weight: 1, accuracy: High
        $x_1_2 = {0b c8 8b 45 ec 31 4d ?? 23 45 ?? 8b 4d ?? f7 d1 23 4d e0 33 c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

