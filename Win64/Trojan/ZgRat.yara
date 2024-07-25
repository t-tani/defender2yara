rule Trojan_Win64_ZgRat_AZ_2147900858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZgRat.AZ!MTB"
        threat_id = "2147900858"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZgRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 ba 65 38 32 38 63 35 61 33 48 89 54 24 1c 48 ba 38 35 37 37 65 34 64 31 48 89 54 24 24 48 ba 63 30 62 37 64 33 34 39 48 89 54 24 2c 48 ba 33 63 36 36 37 31 35 35 48 89 54 24 34 31 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

