rule Trojan_Win64_Disabler_PAHR_2147979802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Disabler.PAHR!MTB"
        threat_id = "2147979802"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Disabler"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {80 00 ad 48 8d 40 01 48 83 e9 01 75}  //weight: 5, accuracy: High
        $x_3_2 = {0f b7 0c 42 66 83 c1 5d 66 41 23 c8 66 89 0c 42 48 ff c0 48 83 f8 0f 72}  //weight: 3, accuracy: High
        $x_1_3 = "-Verb RunAs" wide //weight: 1
        $x_1_4 = "powershell.exe -NoProfile -Command \"Start-Process -FilePath" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

