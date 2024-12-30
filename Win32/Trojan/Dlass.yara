rule Trojan_Win32_Dlass_GQX_2147925907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dlass.GQX!MTB"
        threat_id = "2147925907"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dlass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 a2 0a 00 d5 56 85 48}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dlass_GPPA_2147929276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dlass.GPPA!MTB"
        threat_id = "2147929276"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dlass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 30 0a 00 2c 7c 5e 9c}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

