rule Ransom_Win32_MoonRansom_YAA_2147922988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/MoonRansom.YAA!MTB"
        threat_id = "2147922988"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "MoonRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {33 c0 8a 04 30 30 04 1f ff 46 40 47}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

