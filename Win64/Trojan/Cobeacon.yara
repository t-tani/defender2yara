rule Trojan_Win64_Cobeacon_ARA_2147925943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobeacon.ARA!MTB"
        threat_id = "2147925943"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobeacon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 d2 48 8b c1 49 f7 f1 42 0f b6 04 12 42 30 04 01 48 ff c1 48 3b cf 72 e7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
