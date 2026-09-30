rule Trojan_Win64_Valley_MK_2147979421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Valley.MK!MTB"
        threat_id = "2147979421"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Valley"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_35_1 = {41 0f b6 0c 2e 4d 8d 5b 01 4c 8b 03 b8 dd 47 70 1f f7 e1 8b c1 45 8b ca 2b c2 d1 e8 03 c2 c1 e8 08 69 c0 c8 01 00 00 2b c8 b8 cd cc cc cc 41 f7 e2 80 c1 36 48 8d 45 01 43 30 4c 03 ff 33 ed c1 ea 03 41 ff c2 8d 0c 92 03 c9 44 3b c9 48 0f 45 e8 44 3b d6}  //weight: 35, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

