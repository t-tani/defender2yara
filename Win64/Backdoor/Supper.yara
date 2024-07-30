rule Backdoor_Win64_Supper_A_2147917250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Supper.A!ldr"
        threat_id = "2147917250"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Supper"
        severity = "Critical"
        info = "ldr: loader component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 04 1f 48 33 45 f0 48 89 04 1e e8 ?? ?? ?? ?? 48 3b 45 e0 0f 83 ?? ?? ?? ?? 48 31 c9 51 48 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

