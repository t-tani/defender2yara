rule Trojan_Win64_Expiro_AA_2147793770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Expiro.AA!MTB"
        threat_id = "2147793770"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "SplashWindow" ascii //weight: 3
        $x_3_2 = "e&JHZ<lwVoNWj" ascii //weight: 3
        $x_3_3 = "TO|Djiu" ascii //weight: 3
        $x_3_4 = "ShapeCollector.pdb" ascii //weight: 3
        $x_3_5 = "CommandLineToArgvW" ascii //weight: 3
        $x_3_6 = "ShellExecuteExW" ascii //weight: 3
        $x_3_7 = "EtwLogTraceEvent" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Expiro_RPX_2147907534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Expiro.RPX!MTB"
        threat_id = "2147907534"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 91 cc 00 00 00 f7 91 34 01 00 00 48 81 c6 00 04 00 00 48 81 c1 00 04 00 00 48 81 fe 00 c0 08 00 0f 85 ?? ?? ff ff 59 e8 ?? ?? ff ff 48 8b e5 5d 41 5f 41 5e 41 5d 41 5c 41 5b 41 5a 41 59 41 58 5f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Expiro_DC_2147923629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Expiro.DC!MTB"
        threat_id = "2147923629"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 48 83 ec 38 48 85 c9 74 43 48 89 cf 48 8b 71 f0 8b 06 a8 01 75 3d 89 c1 83 c9 01 f0 0f b1 0e a8 01 75 30 48 89 f9 48 89 f2 e8 ?? ?? ?? ?? 8b 86 20 01 00 00 85 c0 7e 33 ff c8 89 86 20 01 00 00 8b 16 83 e2 02 87 16 83 fa 08 73 11 48 83 c4 38 5f 5e}  //weight: 1, accuracy: Low
        $x_1_2 = {49 8b 11 49 89 10 48 8b 16 48 8b 14 c2 48 8b 12 49 89 11 48 8b 16 48 8b 04 c2 4c 89 08}  //weight: 1, accuracy: High
        $x_1_3 = {49 89 c2 49 21 d2 48 c1 e8 02 48 21 d0 4c 01 d0 48 89 c2 48 c1 ea 04 48 01 c2}  //weight: 1, accuracy: High
        $x_1_4 = {49 8b 41 08 48 39 f8 72 08 31 d2 48 f7 f7 48 89 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

