rule Trojan_Win64_XWorm_GPA_2147904521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.GPA!MTB"
        threat_id = "2147904521"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "src\\main.rshttps://107.175.3.10" ascii //weight: 5
        $x_5_2 = ".binhttps://github.comInternet" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

