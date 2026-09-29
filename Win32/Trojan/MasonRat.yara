rule Trojan_Win32_MasonRat_AG_2147979401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MasonRat.AG!MTB"
        threat_id = "2147979401"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MasonRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b c7 c1 e0 ?? 33 f8 8b c7 c1 e8 ?? 33 f8 8b c7 c1 e0 ?? 33 f8 8b c7 c1 e8 ?? 30 04 19 41 3b cd 72}  //weight: 5, accuracy: Low
        $x_2_2 = "persist relaunched, exiting" ascii //weight: 2
        $x_2_3 = "persist Run key set" ascii //weight: 2
        $x_1_4 = "AmsiOpenSession" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

