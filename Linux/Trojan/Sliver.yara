rule Trojan_Linux_Sliver_A_2147824843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Sliver.A!MTB"
        threat_id = "2147824843"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Sliver"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "sliverpb/sliver.proto" ascii //weight: 2
        $x_1_2 = "/bishopfox/sliver/protobuf/sliverpbb" ascii //weight: 1
        $x_1_3 = "sliverpb.Pwd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Linux_Sliver_AC_2147902344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Sliver.AC!MTB"
        threat_id = "2147902344"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Sliver"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 8d 64 24 f8 4d 3b 66 10 0f 86 2f 05 00 00 48 81 ec 88 00 00 00 48 89 ac 24 80 00 00 00 48 8d ac 24 80 00 00 00 48 89 84 24 90 00 00 00 48 89 9c 24 98 00 00 00 48 85 c0 0f 84 d4 04 00 00 8b 48 10 81 f9 6d 54 1a b3 0f 87 57 02 00 00 81 f9 8c 02 25 79 0f 87 30 01 00 00 66 0f 1f 44 00 00 81 f9 fb 7f a2 2e 0f 87 83 00 00 00 81 f9 c5 06 ff 13 75 36}  //weight: 1, accuracy: High
        $x_1_2 = "sliverpb.pwd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Sliver_B_2147902849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Sliver.B!MTB"
        threat_id = "2147902849"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Sliver"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 83 ec 18 48 89 6c 24 10 48 8d 6c 24 10 48 8b 7c 24 20 48 8b 74 24 28 48 8b 54 24 30 48 8b 05 0c f4 ea 00 48 89 e3 48 83 e4 f0 ff d0 48 89 dc 89 44 24 38 48 8b 6c 24 10 48 83 c4 18 c3}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 44 24 08 8b 7c 24 10 48 8b 74 24 18 48 8b 54 24 20 55 48 89 e5 48 83 e4 f0 ff d0 48 89 ec 5d c3}  //weight: 1, accuracy: High
        $x_1_3 = {83 ff 1b 75 f6 b8 00 00 00 00 b9 01 00 00 00 4c 8d 1d 02 23 ee 00 f0 41 0f b1 0b 75 de 48 8b 0d 5c f6 ea 00 4c 8d 05 b5 36 ee 00 4c 8d 0d 0e fa ff ff 48 8b 05 4f f2 ea 00 ff e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Sliver_C_2147912571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Sliver.C!MTB"
        threat_id = "2147912571"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Sliver"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 14 48 85 c0 74 09 48 8b 2c 24 48 83 c4 08 c3 e8 d8 b9 fa ff 90 4c 8d 6c 24 10}  //weight: 1, accuracy: High
        $x_1_2 = {48 85 c0 74 09 48 8b 2c 24 48 83 c4 08 c3 e8 d8 b8 fa ff 90 4c 8d 6c 24 10 4d 39 2c 24 75 e1 49 89 24 24 eb db}  //weight: 1, accuracy: High
        $x_1_3 = {74 21 48 8b 10 48 8b 58 08 0f b6 48 10 0f b6 78 11 48 89 d0 e8 a4 b1 fa ff 48 8b 6c 24 18 48 83 c4 20 c3 e8 d5 b7 fa ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

