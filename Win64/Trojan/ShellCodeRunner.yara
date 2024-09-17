rule Trojan_Win64_ShellCodeRunner_ASR_2147907975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeRunner.ASR!MTB"
        threat_id = "2147907975"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 8b c2 0f b7 00 41 8b c8 c1 c9 08 41 ff c1 03 c8 41 8b c1 49 03 c2 44 33 c1 44 38 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellCodeRunner_NS_2147914182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeRunner.NS!MTB"
        threat_id = "2147914182"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 8b 05 7a 45 45 00 48 89 04 24 48 c7 44 24 08 ?? ?? ?? ?? 48 8b 44 24 30 48 89 44 24 ?? 48 c7 44 24 18 ?? ?? ?? ?? 48 c7 44 24 20}  //weight: 3, accuracy: Low
        $x_3_2 = {45 0f 57 ff 4c 8b 35 d0 5b 4e ?? 65 4d 8b 36 4d 8b 36 48 8b 44 24 ?? 48 8b 6c 24 38}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellCodeRunner_AB_2147921217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeRunner.AB!MTB"
        threat_id = "2147921217"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {71 64 59 20 ef cf 79 da b8 1a ee 34 84 e7 33 2a 98 1c 78 94 73 50 62 dd 43 44 44 3a 90 63 7e 12 6f 4d 87 8b 51 32 2b db 8a 2d 8e 21 23 ef d6 7e af 07 5e 87 7f f5 48 65 18 12 b0 1e 6e 86 e0 8c 77 e0 55 8c c5 07 45 53 8d d5 8d 37 ce b5 72 54 69 98 4c e7 ac 49 ed 35 5b 17 e9 09 7d bc 56 47 c2 17 ce d2 5a 4f d0 9b c8 5f 25 91 09 b8 13 27 7e e4 82 cb 4d 4c 75 58 74 c2 82 df 7f 98 dd 84 57 f5 52 a7 ba bc 31 cf 67 25 64 28 9c 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

