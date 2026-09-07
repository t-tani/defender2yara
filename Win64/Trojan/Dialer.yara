rule Trojan_Win64_Dialer_ARA_2147977673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dialer.ARA!MTB"
        threat_id = "2147977673"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dialer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {80 34 32 0a 8b fe 83 c9 ff 33 c0 42 f2 ae f7 d1 49 3b d1 7c eb}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

