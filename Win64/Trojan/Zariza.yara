rule Trojan_Win64_Zariza_MX_2147926837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zariza.MX!MTB"
        threat_id = "2147926837"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zariza"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hijack.dll" ascii //weight: 1
        $x_1_2 = "zig-loader.dll" ascii //weight: 1
        $x_2_3 = "deco.dll" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

