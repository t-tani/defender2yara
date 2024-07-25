rule Trojan_Win64_Bazar_EA_2147853200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bazar.EA!MTB"
        threat_id = "2147853200"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 89 84 24 f8 00 00 00 b8 0a 00 00 00 48 01 f8 48 89 44 24 78 bd 03 00 00 00 48 89 c8 48 09 e8 48 89 84 24 f0 00 00 00 48 09 cb 48 89 c8 48 09 e8 48 89 84 24 e8 00 00 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

