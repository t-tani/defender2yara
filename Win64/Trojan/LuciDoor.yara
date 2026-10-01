rule Trojan_Win64_LuciDoor_AA_2147979620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LuciDoor.AA!MTB"
        threat_id = "2147979620"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LuciDoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_9_1 = {8a 44 0e ff 30 04 0e 46 83 fe}  //weight: 9, accuracy: High
        $x_11_2 = {8a 44 31 ff 30 04 31 49 85 c9 7f}  //weight: 11, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

