rule Trojan_Win32_RHADAMANTHYS_DA_2147919686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RHADAMANTHYS.DA!MTB"
        threat_id = "2147919686"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RHADAMANTHYS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "61"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "NBDeviceGetIdA" ascii //weight: 10
        $x_10_2 = "NBDeviceGetState" ascii //weight: 10
        $x_10_3 = "NBDeviceSupportsNBUApi" ascii //weight: 10
        $x_10_4 = "NBErrorsGetMessageA" ascii //weight: 10
        $x_10_5 = "NBErrorsSetLastA" ascii //weight: 10
        $x_10_6 = "NBUAbort" ascii //weight: 10
        $x_1_7 = "AlphaBlend" ascii //weight: 1
        $x_1_8 = "TransparentB" ascii //weight: 1
        $x_1_9 = "CreateFontPacka" ascii //weight: 1
        $x_1_10 = "GradientFill" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

