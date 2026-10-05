rule Backdoor_Win64_CornFlake_E_2147979705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/CornFlake.E!dha"
        threat_id = "2147979705"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "CornFlake"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "src/chromekatz.rs" ascii //weight: 1
        $x_1_2 = "src/cfgprotect.rs" ascii //weight: 1
        $x_1_3 = "src/keylog.rs" ascii //weight: 1
        $x_1_4 = "src/chromeabe.rs" ascii //weight: 1
        $x_1_5 = "staying under cover" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win64_CornFlake_F_2147979727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/CornFlake.F"
        threat_id = "2147979727"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "CornFlake"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "61"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cookies.sqlite" ascii //weight: 1
        $x_1_2 = "rootsbookmark_barsynced" ascii //weight: 1
        $x_1_3 = "HistoryLocal" ascii //weight: 1
        $x_1_4 = "sqlite Login" ascii //weight: 1
        $x_1_5 = "WaterfoxProfiles" ascii //weight: 1
        $x_10_6 = "\\Google\\Chrome\\User Data" ascii //weight: 10
        $x_10_7 = "\\Microsoft\\Edge\\User Data" ascii //weight: 10
        $x_10_8 = "\\BraveSoftware\\Brave-Browser\\User Data" ascii //weight: 10
        $x_10_9 = "\\Vivaldi\\User Data" ascii //weight: 10
        $x_10_10 = "\\Yandex\\YandexBrowser\\User Data" ascii //weight: 10
        $x_10_11 = "\\Thorium\\User Data" ascii //weight: 10
        $x_10_12 = "\\Opera Stable\\User Data" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 1 of ($x_1_*))) or
            ((7 of ($x_10_*))) or
            (all of ($x*))
        )
}

