rule Trojan_Win64_sidewinder_PAHV_2147979517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/sidewinder.PAHV!MTB"
        threat_id = "2147979517"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "sidewinder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 8d 42 01 99 41 f7 f9 48 63 fa 0f b6 44 3c 10 49 89 fa 89 c1 01 f0 99 41 f7 f9 48 63 c2}  //weight: 2, accuracy: High
        $x_3_2 = {8a 54 04 10 48 89 c6 88 54 3c 10 88 4c 04 10 02 4c 3c 10 0f b6 c9 8a 4c 0c 10 42 32 0c 03 43 88 0c 03 49 ff c0 49 83 f8 0e 75}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

