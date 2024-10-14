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

rule Trojan_MacOS_ProxyAgent_B_2147923518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/ProxyAgent.B!MTB"
        threat_id = "2147923518"
        type = "Trojan"
        platform = "MacOS: "
        family = "ProxyAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 89 e5 41 57 41 56 53 48 83 ec 68 48 89 fb 48 8b 05 29 de 55 00 48 8b 00 48 89 45 e0 c7 45 9c ff ff ff ff 48 8d 75 9c 4c 8d 75 8c bf 03 00 00 00 4c 89 f2 e8 16 b4 2b 00 4c 8d 7d a0 4c 89 ff e8 f2 b3 2b 00 48 8d 75 90 4c 89 ff e8 ec b3 2b 00 48 8b 45 90}  //weight: 1, accuracy: High
        $x_1_2 = {e8 cc b3 2b 00 85 db 75 1b 48 8b 05 b1 dd 55 00 48 8b 00 48 3b 45 e0 75 14 48 83 c4 68 5b 41 5e 41 5f 5d c3 89 df e8 46 00 00 00 eb dc e8 99 b3 2b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

