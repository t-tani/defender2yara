rule Trojan_Win64_Malgentz_C_2147920878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Malgentz.C!MTB"
        threat_id = "2147920878"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Malgentz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 0f 28 ca 0f 28 ee 0f c6 ee 55 f3 0f 59 cd 0f 28 c7 f3 0f 59 c6 f3 0f 58 c8 41 0f 28 c0 0f 28 e6 0f c6 e6 aa f3 0f 59 c4 f3 0f 58 c8 41 0f 28 c1 0f 28 de 0f c6 de ff f3 0f 59 c3 f3 0f 58 c8 0f 57 c0 f3 0f 5a c1 f2 0f 11 45 20 41 0f 28 d2 41 0f c6 d2 55 f3 0f 59 d5 0f 28 c7 0f c6 c7 55 f3 0f 59 c6 f3 0f 58 d0 41 0f 28 c8 41 0f c6 c8 55 f3 0f 59 cc f3 0f 58 d1 41 0f 28 c1 41 0f c6 c1 55 f3 0f 59 c3 f3 0f 58 d0 0f 57 c0 f3 0f 5a c2 f2 0f 11 45 b0 45 0f c6 d2 aa f3 44 0f 59 d5 0f c6 ff aa f3 0f 59 fe f3 44 0f 58 d7 45 0f c6 c0 aa f3 44 0f 59 c4 f3 45 0f 58 d0 45 0f c6 c9 aa f3 44 0f 59 cb f3 45 0f 58 d1 0f 57 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Malgentz_AB_2147921116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Malgentz.AB!MTB"
        threat_id = "2147921116"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Malgentz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 44 24 20 02 00 00 00 48 b8 02 01 25 1d 12 2c 16 5e 48 89 44 24 30 48 b8 06 f2 25 03 16 ff 7f 0f 48 89 44 24 38 48 8d 44 24 28 48 8b f8 33 c0 b9 08 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {89 44 24 30 8b 44 24 30 48 69 c0 20 04 00 00 48 63 4c 24 38 48 8b 94 24 d8 00 00 00 48 03 8c 02 10 04 00 00 48 8b c1 b9 04 00 00 00 48 6b c9 00 48 8b d0 48 8b 84 24 d0 00 00 00 8b 0c 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

