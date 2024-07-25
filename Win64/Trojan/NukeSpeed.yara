rule Trojan_Win64_NukeSpeed_MK_2147781101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/NukeSpeed.MK!MTB"
        threat_id = "2147781101"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "NukeSpeed"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 54 04 [0-1] 48 ff c0 42 32 [0-3] 48 83 f8 [0-1] 48 0f 44 c1 41 88 14 18 49 ff c0 49 83 f8 [0-1] 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_NukeSpeed_MK_2147781101_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/NukeSpeed.MK!MTB"
        threat_id = "2147781101"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "NukeSpeed"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 74 05 f7 [0-1] 80 74 05 f8 00 48 83 c0 02 48 83 f8 [0-1] 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {41 0f b6 4c 10 [0-1] 48 ff c2 41 32 cc 48 ff cf 88 4a ff 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

