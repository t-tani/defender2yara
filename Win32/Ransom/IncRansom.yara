rule Ransom_Win32_IncRansom_YAA_2147852703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/IncRansom.YAA!MTB"
        threat_id = "2147852703"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "IncRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Wallpaper" wide //weight: 1
        $x_1_2 = "INC-README" wide //weight: 1
        $x_1_3 = "background-image.jpg" wide //weight: 1
        $x_1_4 = "SW5jLiBSYW5zb213YXJlDQoNCldlIGhhdmUgaGFja2VkIHlvdSBhbmQg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

