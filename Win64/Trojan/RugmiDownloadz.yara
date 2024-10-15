rule Trojan_Win64_RugmiDownloadz_A_2147923635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RugmiDownloadz.A!MTB"
        threat_id = "2147923635"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RugmiDownloadz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3b 00 53 d8 3b 00 63 d8 3b 00 74 d8 3b 00 97 d8 3b 00 a5 d8 3b 00 ba d8 3b 00 c6 d8 3b 00 df d8 3b 00 f6 d8 3b 00 16 d9 3b 00 2d d9 3b 00 47 d9 3b 00 55 d9 3b 00 6e d9 3b 00 87 d9 3b 00 9d d9 3b 00 af d9 3b 00 d7 d9 3b 00 f5 d9 3b 00 1f da 3b 00 49 da 3b 00 66 da 3b 00 8c da 3b 00 ab da 3b 00 bd da 3b 00 d4 da}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

