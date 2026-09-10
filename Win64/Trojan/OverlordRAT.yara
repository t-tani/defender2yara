rule Trojan_Win64_OverlordRAT_AA_2147977891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/OverlordRAT.AA!MTB"
        threat_id = "2147977891"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "OverlordRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_16_1 = {0f b6 d2 0f b6 94 14 ?? ?? ?? ?? 30 54 0b ff 48 8d 14 0f 48 ff c2 48 ff c1 48 83 fa}  //weight: 16, accuracy: Low
        $x_4_2 = "badata_x64.dll" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_OverlordRAT_AB_2147977892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/OverlordRAT.AB!MTB"
        threat_id = "2147977892"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "OverlordRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_16_1 = {46 0f b6 8c 0c ?? ?? ?? ?? 45 30 08 49 ff c0 fe c2 49 39 c0 72}  //weight: 16, accuracy: Low
        $x_4_2 = "badata_x64.dll" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

