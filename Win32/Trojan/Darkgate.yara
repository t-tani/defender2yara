rule Trojan_Win32_Darkgate_IP_2147895643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Darkgate.IP!MTB"
        threat_id = "2147895643"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Darkgate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zLAxuU0kQKf3sWE7ePRO2imyg9GSpVoYC6rhlX48ZHnvjJDBNFtMd1I5acwbqT+=" ascii //weight: 1
        $x_1_2 = {8a 1a 8a 4e 06 eb e8 8a 5c 31 06 32 1c 11}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Darkgate_YAB_2147928173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Darkgate.YAB!MTB"
        threat_id = "2147928173"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Darkgate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 89 d8 83 c0 ?? 48 48 48 48}  //weight: 1, accuracy: Low
        $x_10_2 = {48 48 48 58 31 d2 f7 f3 8a 04 16 30 04 0f}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

