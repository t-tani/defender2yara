rule Trojan_Win64_Ravatar_HM_2147980000_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Ravatar.HM!MTB"
        threat_id = "2147980000"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Ravatar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 50 9c 49 b8 3d 4c 0a f0 19 12 96 0f e8 30 c3 fd ff d1 4b 28 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

