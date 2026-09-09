rule Trojan_Win64_BlankLizard_A_2147977784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlankLizard.A"
        threat_id = "2147977784"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlankLizard"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 6f 66 74 77 61 72 65 5c 53 79 73 55 70 64 61 74 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {55 70 64 61 74 65 43 6f 75 6e 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {52 00 73 00 61 00 55 00 70 00 64 00 61 00 74 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

