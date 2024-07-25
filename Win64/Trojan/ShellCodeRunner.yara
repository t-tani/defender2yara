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

