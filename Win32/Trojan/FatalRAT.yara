rule Trojan_Win32_FatalRAT_B_2147898608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FatalRAT.B!MTB"
        threat_id = "2147898608"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FatalRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c2 30 54 3e ?? 46 3b b5 1b 00 8a 44 3e ?? 32 85 ?? ?? ff ff 88 44 3e ?? e8 ?? ?? ?? ?? 99 f7 bd ?? ?? ff ff fe}  //weight: 2, accuracy: Low
        $x_2_2 = {8a 04 3e 32 85 ?? ?? ff ff 88 04 3e e8 ?? ?? ?? ?? 99 f7 bd ?? ?? ff ff fe c2 30 14 3e 46 3b b5}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_FatalRAT_EC_2147903130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FatalRAT.EC!MTB"
        threat_id = "2147903130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FatalRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KeyboardManager" ascii //weight: 1
        $x_1_2 = "DockingManagers" ascii //weight: 1
        $x_1_3 = "RestartByRestartManager:" ascii //weight: 1
        $x_1_4 = "ShellCodeLoader.pdb" ascii //weight: 1
        $x_1_5 = "WINDOWS\\system32\\1.bin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

