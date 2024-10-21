rule Trojan_Win32_Autoitinject_PQH_2147920847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.PQH!MTB"
        threat_id = "2147920847"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FILEINSTALL" ascii //weight: 1
        $x_1_2 = "@TEMPDIR" ascii //weight: 1
        $x_1_3 = "DLLCALL" ascii //weight: 1
        $x_5_4 = "k99DD04AAe99DD04AAr99DD04AAn99DD04AAe99DD04AAl99DD04AA399DD04AA299DD04AA" ascii //weight: 5
        $x_7_5 = "b99DD04AAy99DD04AAt99DD04AAe99DD04AA" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Autoitinject_PSH_2147920916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.PSH!MTB"
        threat_id = "2147920916"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FILEINSTALL" ascii //weight: 1
        $x_1_2 = "@TEMPDIR" ascii //weight: 1
        $x_1_3 = "DLLCALL" ascii //weight: 1
        $x_5_4 = "30A022k30A022e30A022r30A022n30A022e30A022l30A022330A022230A022" ascii //weight: 5
        $x_7_5 = "30A022u30A022s30A022e30A022r30A022330A022230A022" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Autoitinject_PPH_2147921867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.PPH!MTB"
        threat_id = "2147921867"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@TEMPDIR" ascii //weight: 1
        $x_1_2 = "DLLCALL" ascii //weight: 1
        $x_5_3 = "k950015789e950015789r950015789n950015789e950015789l95001578939500157892950015789" ascii //weight: 5
        $x_7_4 = "u950015789s950015789e950015789r95001578939500157892950015789" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Autoitinject_PPCH_2147921869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.PPCH!MTB"
        threat_id = "2147921869"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@TEMPDIR" ascii //weight: 1
        $x_1_2 = "DLLCALL" ascii //weight: 1
        $x_5_3 = "k2qtc53dse2qtc53dsr2qtc53dsn2qtc53dse2qtc53dsl2qtc53ds32qtc53ds22qtc53ds" ascii //weight: 5
        $x_7_4 = "u2qtc53dss2qtc53dse2qtc53dsr2qtc53ds32qtc53ds22qtc53ds" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Autoitinject_PPEH_2147921871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.PPEH!MTB"
        threat_id = "2147921871"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@TEMPDIR" ascii //weight: 1
        $x_1_2 = "DLLCALL" ascii //weight: 1
        $x_5_3 = "k5s0ftwm6e5s0ftwm6r5s0ftwm6n5s0ftwm6e5s0ftwm6l5s0ftwm635s0ftwm625s0ftwm6" ascii //weight: 5
        $x_7_4 = "u5s0ftwm6s5s0ftwm6e5s0ftwm6r5s0ftwm635s0ftwm625s0ftwm6" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Autoitinject_PPFH_2147921872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.PPFH!MTB"
        threat_id = "2147921872"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@TEMPDIR" ascii //weight: 1
        $x_1_2 = "DLLCALL" ascii //weight: 1
        $x_5_3 = "k7IfgcdZxe7IfgcdZxr7IfgcdZxn7IfgcdZxe7IfgcdZxl7IfgcdZx37IfgcdZx27IfgcdZx" ascii //weight: 5
        $x_7_4 = "u7IfgcdZxs7IfgcdZxe7IfgcdZxr7IfgcdZx37IfgcdZx27IfgcdZx" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Autoitinject_PHIH_2147921874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.PHIH!MTB"
        threat_id = "2147921874"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@TEMPDIR" ascii //weight: 1
        $x_1_2 = "DLLCALL" ascii //weight: 1
        $x_5_3 = "k0qk5dd92e0qk5dd92r0qk5dd92n0qk5dd92e0qk5dd92l0qk5dd9230qk5dd9220qk5dd92" ascii //weight: 5
        $x_7_4 = "u0qk5dd92s0qk5dd92e0qk5dd92r0qk5dd9230qk5dd9220qk5dd92" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Autoitinject_SPIH_2147922126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.SPIH!MTB"
        threat_id = "2147922126"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@TEMPDIR" ascii //weight: 1
        $x_1_2 = "DLLCALL" ascii //weight: 1
        $x_5_3 = "k6wcRq90de6wcRq90dr6wcRq90dn6wcRq90de6wcRq90dl6wcRq90d36wcRq90d26wcRq90d.6wcRq90dd6wcRq90dl6wcRq90dl6wcRq90d" ascii //weight: 5
        $x_3_4 = "u6wcRq90ds6wcRq90de6wcRq90dr6wcRq90d36wcRq90d26wcRq90d.6wcRq90dd6wcRq90dl6wcRq90dl6wcRq90d" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Autoitinject_PHOH_2147922345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.PHOH!MTB"
        threat_id = "2147922345"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@TEMPDIR" ascii //weight: 1
        $x_1_2 = "DLLCALL" ascii //weight: 1
        $x_5_3 = "k8tqp05tss9e8tqp05tss9r8tqp05tss9n8tqp05tss9e8tqp05tss9l8tqp05tss938tqp05tss928tqp05tss9" ascii //weight: 5
        $x_7_4 = "u8tqp05tss9s8tqp05tss9e8tqp05tss9r8tqp05tss938tqp05tss928tqp05tss9" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Autoitinject_PPQH_2147922513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.PPQH!MTB"
        threat_id = "2147922513"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@TEMPDIR" ascii //weight: 1
        $x_1_2 = "DLLCALL" ascii //weight: 1
        $x_5_3 = "k2sYcsae2sYcsar2sYcsan2sYcsae2sYcsal2sYcsa32sYcsa22sYcsa" ascii //weight: 5
        $x_7_4 = "u2sYcsas2sYcsae2sYcsar2sYcsa32sYcsa22sYcsa" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Autoitinject_PHHA_2147923118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.PHHA!MTB"
        threat_id = "2147923118"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DLLCALL" ascii //weight: 1
        $x_1_2 = "@TEMPDIR" ascii //weight: 1
        $x_5_3 = "kNBeRIrBVnWSeQMlJH3TO2DY" ascii //weight: 5
        $x_7_4 = "VNBiRIrBVtWSuQMaJHlTOADYlTAlFEoMBcST" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Autoitinject_PIIH_2147923709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.PIIH!MTB"
        threat_id = "2147923709"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DLLCALL" ascii //weight: 1
        $x_1_2 = "@TEMPDIR" ascii //weight: 1
        $x_5_3 = "kIS5XeIS5XrIS5XnIS5XeIS5XlIS5X3IS5X2IS5X" ascii //weight: 5
        $x_7_4 = "VIS5XiIS5XrIS5XtIS5XuIS5XaIS5XlIS5XPIS5XrIS5XoIS5XtIS5XeIS5XcIS5XtIS5X" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Autoitinject_SPGH_2147924125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.SPGH!MTB"
        threat_id = "2147924125"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "k2du3we2du3wr2du3wn2du3we2du3wl2du3w32du3w22du3w.2du3wd2du3wl2du3wl2du3w" ascii //weight: 5
        $x_3_2 = "u2du3ws2du3we2du3wr2du3w32du3w22du3w.2du3wd2du3wl2du3wl2du3w" ascii //weight: 3
        $x_1_3 = "\"D\" & \"ll\" & \"C\" & \"all" ascii //weight: 1
        $x_1_4 = "@Te\" & \"mpDir" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Autoitinject_SPHJ_2147924214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.SPHJ!MTB"
        threat_id = "2147924214"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "u8zgbxs8zgbxe8zgbxr8zgbx38zgbx28zgbx.8zgbxd8zgbxl8zgbxl8zgbx" ascii //weight: 5
        $x_3_2 = "k8zgbxe8zgbxr8zgbxn8zgbxe8zgbxl8zgbx38zgbx28zgbx.8zgbxd8zgbxl8zgbxl8zgbx" ascii //weight: 3
        $x_1_3 = "DllCall" ascii //weight: 1
        $x_1_4 = "@TEMPDIR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

