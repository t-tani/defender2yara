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

