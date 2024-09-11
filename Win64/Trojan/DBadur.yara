rule Trojan_Win64_DBadur_AMAA_2147920894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DBadur.AMAA!MTB"
        threat_id = "2147920894"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DBadur"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {80 c1 03 48 63 c2 42 30 4c 08 0a 41 ff 01 eb ?? 8d 41 05 44 3b c0 75 ?? 80 c1 04 48 63 c2 42 30 4c 08 0a 41 ff 01 eb 95 48 63 ca 8d 42 ?? 42 30 44 09 0a ff c2 83 fa 0e 72}  //weight: 3, accuracy: Low
        $x_2_2 = "https://05412.net/zmm" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

