rule TrojanSpy_Win32_AshamedWages_A_2147923568_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/AshamedWages.A!dha"
        threat_id = "2147923568"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "AshamedWages"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 77 08 ff 75 08 e8 13 ff ff ff 89 07 83 c7 0c 83 3f ff 75 eb}  //weight: 1, accuracy: High
        $x_1_2 = {ac 30 d0 aa c1 ca 08 e2 f7 61 c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

