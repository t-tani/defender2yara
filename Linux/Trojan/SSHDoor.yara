rule Trojan_Linux_SSHDoor_C_2147914066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SSHDoor.C!MTB"
        threat_id = "2147914066"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SSHDoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 57 41 56 49 89 f6 41 55 41 54 55 89 fd 53 48 81 ec 98 09 00 00 48 8b 3e 64 48 8b 04 25 28 00 00 00 48 89 84 24 88 09 00 00 31 c0 c7 44 24 34 01 00 00 00 c7 44 24 60 ff ff ff ff c7 44 24 64 ff ff ff ff e8 37 ae 04 00 8d 7d 01}  //weight: 1, accuracy: High
        $x_1_2 = {53 31 c9 ba 01 00 00 00 31 f6 48 89 fb 48 83 ec 10 64 48 8b 04 25 28 00 00 00 48 89 44 24 08 31 c0 e8 0a fc ff ff 31 d2 85 c0 48 0f 45 d3 48 8b 4c 24 08 64 48 33 0c 25 28 00 00 00 75 09 48 83 c4 10 48 89 d0 5b c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

