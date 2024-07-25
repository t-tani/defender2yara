rule Trojan_Win64_MedusaStealer_PD_2147905921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MedusaStealer.PD!MTB"
        threat_id = "2147905921"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MedusaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {46 8a 04 02 41 b9 15 00 00 00 31 d2 41 f7 f1 8b 44 24 04 41 89 d1 48 8b 54 24 08 4d 63 c9 46 32 04 0a 48 63 d0 44 88 04 11}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

