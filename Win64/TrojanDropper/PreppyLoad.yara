rule TrojanDropper_Win64_PreppyLoad_E_2147978124_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/PreppyLoad.E!dha"
        threat_id = "2147978124"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "PreppyLoad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "X7m!qZ@9vP#YfG$5bL&K^2d*TNhJC8rA" ascii //weight: 1
        $x_1_2 = "n/.m?x8ta}!6USa}!%#/<Cq5A_Cq?djv" ascii //weight: 1
        $x_1_3 = "NetSvcInst_v1_Rundll32.dll" ascii //weight: 1
        $x_1_4 = "f2F+{i7&PK#9-W9kAi*T" ascii //weight: 1
        $x_1_5 = {00 00 00 00 25 00 73 00 5c 00 77 00 69 00 6e 00 33 00 32 00 6b 00 2e 00 73 00 79 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = "cmd.exe /c move /Y %s %s" wide //weight: 1
        $x_1_7 = {61 00 74 00 2b 00 00 00 5b 25 30 34 64 2d 25 30 32 64 2d 25 30 32 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 5d 20 25 73 0a 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = "CRYPTO_lockW" ascii //weight: 1
        $x_1_9 = {25 00 73 00 20 00 25 00 73 00 00 00 00 00 00 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 00 00}  //weight: 1, accuracy: High
        $x_1_10 = {36 e4 77 63 c7 85 ?? ?? ?? ?? 78 bf 3c e2 c7 85 ?? ?? ?? ?? 49 86 85 93}  //weight: 1, accuracy: Low
        $x_1_11 = {36 e4 77 63 c7 ?? ?? 78 bf 3c e2 c7 ?? ?? 49 86 85 93 c6 ?? ?? 5b}  //weight: 1, accuracy: Low
        $x_1_12 = {8b 81 00 20 00 00 ?? 8b ?? ?? 8b ?? ?? 81 ?? ff 03 00 00 ?? 8d ?? f6 ?? 8d ?? f4 ?? 81 ?? ff 03 00 00 ?? 8d ?? 01 ?? e3 ff 03 00 00 ?? 8d ?? fd 81 ?? ff 03 00 00 ?? 81 ?? ff 03 00 00 ?? 8d ?? ?? 3d 00 04 00 00}  //weight: 1, accuracy: Low
        $x_1_13 = {8b 83 00 20 00 00 ?? 33 ?? ?? 83 ?? 04 ff ?? ?? 89 ?? 04 20 00 00 ?? 83 ?? 04 ?? ff 07 00 00 89 ?? 00 20 00 00 8b ?? fc ?? 33 ?? 89 ?? fc}  //weight: 1, accuracy: Low
        $x_1_14 = {66 66 0f 1f 84 00 00 00 00 00 0f b6 ?? ?? ff ?? 32 ?? ?? ?? 20 00 00 88 ?? ?? 8b ?? ?? 3b}  //weight: 1, accuracy: Low
        $x_1_15 = {41 8b c0 d1 e8 41 33 c0 c1 e8 03 41 33 c0 d1 e8 41 33 c0 41 81 e0 ff ff 3f 00 45 03 c0 c1 e8 11}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

