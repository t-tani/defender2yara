rule Worm_Win32_Bundpil_ASFG_2147904264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bundpil.ASFG!MTB"
        threat_id = "2147904264"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bundpil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {4a 81 ca 00 ff ff ff 42 89 95 ?? ?? ff ff 8b 55 fc 03 95 ?? ?? ff ff 0f b6 02 8b 8d ?? ?? ff ff 0f b6 91 ?? ?? ?? ?? 33 c2 8b 4d ?? 03 8d ?? ?? ff ff 88 01 e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

