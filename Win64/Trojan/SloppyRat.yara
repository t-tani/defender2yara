rule Trojan_Win64_SloppyRat_DA_2147978041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SloppyRat.DA!MTB"
        threat_id = "2147978041"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SloppyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {33 44 0b a1 a8 7e e9 7d 09 c3 1d dd 25 ee 56 19 77 33 8d 26 de fc 15 1c 53 78 9a ba d3 f8 05 dc 32 57 07 ba a8 45 64 7e 06 68 59 cc 33 9f 4b 32 74 45 8c cf cc f0 12 3e 7e 6b 9a bc d4 f0 07 31 37 9a 06 8d ae 7f 60 72 d1 4d 74 db 11 c7 43 22 74 35 9a bc df f0 4e 69 56 7f 9b bc de f1 0a 12 30 44 1a aa ae 68 70 76 0f 5c 74 ca c5 ec 42 32 75 1d 8e bc de fa 7d 21 56 78 90 ce d5 f0 11 52 5c 52 01 ab a4 62 75 62 27 5a 74 ca 1f fb bc 33 67 3d 8b b4 f3 de 12}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_SloppyRat_YBD_2147978094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SloppyRat.YBD!MTB"
        threat_id = "2147978094"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SloppyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {83 e2 02 0f b6 14 10 41 30 54 08 ?? 48 83 f9 ?? 74 ?? 89 ca 83 e2 ?? 0f b6 14 10 41 30 14 08}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

