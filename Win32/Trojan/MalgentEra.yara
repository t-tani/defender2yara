rule Trojan_Win32_MalgentEra_A_2147919035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MalgentEra.A!MTB"
        threat_id = "2147919035"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MalgentEra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 f4 83 79 1c 01 89 55 f8 75 4d 57 8b 79 0c 85 ff 74 2e 8b ca 56 0f b7 34 53 8d 46 d0 83 f8 09 77 19 66 89 74 0d f4 83 c1 02 83 f9 08 73 38 33 c0 66 89 44 0d f4 83 f9 06 74 05 42 3b d7 72 d6 5e 68}  //weight: 1, accuracy: High
        $x_1_2 = "eval(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MalgentEra_B_2147919036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MalgentEra.B!MTB"
        threat_id = "2147919036"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MalgentEra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ef eb f9 ca 0b 9b fc cb ee eb f9 ca 0b 9b fa cb ed eb f9 ca 0b 9b fd cb fa eb f9 ca 0b 9b 8c be 4e bf 9c ae fe bf 8c ad be bf 9c a0 b9 bf 1c be be bf 9c a0 b9 b0 6c ae ee bf 9c a0 b9 bf bc be ee bf 9c a5 26}  //weight: 1, accuracy: High
        $x_1_2 = "eval(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

