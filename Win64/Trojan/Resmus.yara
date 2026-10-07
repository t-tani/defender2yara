rule Trojan_Win64_Resmus_HM_2147979831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Resmus.HM!MTB"
        threat_id = "2147979831"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Resmus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 0f b6 04 0f 41 31 f0 44 88 04 08 48 ff c1 48 39 ca 7f ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

