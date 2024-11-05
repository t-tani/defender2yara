rule Trojan_Win64_FrostLizzard_C_2147925362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FrostLizzard.C!dha"
        threat_id = "2147925362"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FrostLizzard"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 44 24 40 33 d2 48 8b 44 24 40 8b 48 ?? e8 4e fd ff ff 48 89 84 24 ?? 00 00 00 48 ?? 44 24 40}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

