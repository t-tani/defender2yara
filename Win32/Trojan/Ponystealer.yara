rule Trojan_Win32_Ponystealer_RC_2147898498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ponystealer.RC!MTB"
        threat_id = "2147898498"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ponystealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {9a 20 28 de 16 6e 32 13 01 09 28 4c c8 17 6f 75 19}  //weight: 1, accuracy: High
        $x_1_2 = "candida poofter foredoom burble prangs pleading genealog" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

