rule Trojan_Win64_Reconyc_2147807388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Reconyc.lmnq!MTB"
        threat_id = "2147807388"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Reconyc"
        severity = "Critical"
        info = "lmnq: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2a a0 db df 45 f5 33 b6 ?? ?? ?? ?? 6b e5 59 d3 e0 33 a8 ?? ?? ?? ?? e0 f1 64 b7 02 30 8a ?? ?? ?? ?? 7c e4}  //weight: 10, accuracy: Low
        $x_2_2 = "sloader.exe" ascii //weight: 2
        $x_2_3 = "ShellExecuteExW" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

