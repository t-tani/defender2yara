rule Trojan_Win64_ClearFake_YAA_2147920970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClearFake.YAA!MTB"
        threat_id = "2147920970"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClearFake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 45 e3 48 31 45 92 89 55 84 28 75 f1 b9}  //weight: 1, accuracy: High
        $x_1_2 = {44 30 27 48 8d 05 ?? ?? ?? ?? 50 53 57 56 41 55 41 54 55 48 89 e5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

