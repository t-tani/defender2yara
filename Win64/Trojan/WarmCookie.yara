rule Trojan_Win64_WarmCookie_CCJH_2147918885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/WarmCookie.CCJH!MTB"
        threat_id = "2147918885"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "WarmCookie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 03 c8 48 8b c1 0f b6 00 0f b6 4c 24 20 48 8b 54 24 40 0f b6 4c 0a 02 33 c1 48 8b 4c 24 28 48 8b 54 24 50 48 03 d1 48 8b ca 88 01}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

