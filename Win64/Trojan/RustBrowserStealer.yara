rule Trojan_Win64_RustBrowserStealer_A_2147978129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RustBrowserStealer.A"
        threat_id = "2147978129"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RustBrowserStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {45 31 ff 42 0f b6 14 3b 83 f2 55 4c 89 f1 e8 ?? ?? ?? ?? 49 ff c7 4c 39 ff 75 e8 48 8b 44 24 38 48 89 46 10 0f 10 44 24 28 0f 11 06}  //weight: 8, accuracy: Low
        $x_6_2 = {48 89 f9 e8 ?? ?? ?? ?? 41 b8 04 00 00 00 48 89 d9 48 8d 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 41 b8 0b 00 00 00 48 89 f9 48 8d 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 80 bc 24 ?? ?? ?? ?? 06}  //weight: 6, accuracy: Low
        $x_2_3 = "dump_browser" ascii //weight: 2
        $x_2_4 = "powershell-NoProfile-NonInteractive-Command" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 2 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_6_*))) or
            (all of ($x*))
        )
}

