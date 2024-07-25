rule Trojan_Win64_RustStealer_RPY_2147902566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RustStealer.RPY!MTB"
        threat_id = "2147902566"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RustStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Fud Me by New Coder Rust" ascii //weight: 1
        $x_1_2 = "Secure_Vortex" ascii //weight: 1
        $x_1_3 = "fhnir" ascii //weight: 1
        $x_1_4 = "NtWriteVirtualMemory" ascii //weight: 1
        $x_1_5 = "panicked" ascii //weight: 1
        $x_1_6 = "GoAway" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

