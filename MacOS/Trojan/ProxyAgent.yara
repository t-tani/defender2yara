rule Trojan_MacOS_ProxyAgent_A_2147918314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/ProxyAgent.A!MTB"
        threat_id = "2147918314"
        type = "Trojan"
        platform = "MacOS: "
        family = "ProxyAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 4c 8b 34 25 30 00 00 00 48 8b 05 87 da 5c 00 48 8b 0c 24 48 89 ca 48 29 c1 0f 1f 44 00 00 48 85 c9 7f 0f b8 01 00 00 00 48 8b 6c 24 08 48 83 c4 10}  //weight: 1, accuracy: High
        $x_1_2 = {0f 57 d2 f2 48 0f 2a d3 f2 0f 58 d0 f2 0f 5c c8 0f 57 c0 f2 48 0f 2a c1 f2 0f 59 c1 f2 0f 10 0d e4 f1 39 00 f2 0f 59 c8 f2 0f 58 d1 f2 0f 10 05 c4 f2 39 00 f2 0f 5c d0 0f 57 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

