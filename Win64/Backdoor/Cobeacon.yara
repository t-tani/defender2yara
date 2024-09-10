rule Backdoor_Win64_Cobeacon_ARA_2147920813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Cobeacon.ARA!MTB"
        threat_id = "2147920813"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobeacon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {80 32 77 48 8d 52 01 41 ff c0 48 8d 4c 24 ?? 48 [0-6] 48 ff c0 [0-4] 75 ?? 49 63 c8 48 3b c8 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
