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

rule Trojan_Win32_Autoitinject_PNHH_2147924470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.PNHH!MTB"
        threat_id = "2147924470"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {22 00 44 00 6c 00 22 00 20 00 26 00 20 00 22 00 6c 00 43 00 61 00 6c 00 6c 00 28 00 [0-20] 28 00 22 00 22 00 6c 00 66 00 73 00 6f 00 66 00 6d 00 34 00 33 00 22 00 22 00 29 00 2c 00 20 00 00 28 00 22 00 22 00 71 00 75 00 73 00 22 00 22 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {22 44 6c 22 20 26 20 22 6c 43 61 6c 6c 28 [0-20] 28 22 22 6c 66 73 6f 66 6d 34 33 22 22 29 2c 20 00 28 22 22 71 75 73 22 22 29}  //weight: 2, accuracy: Low
        $x_2_3 = {22 00 44 00 6c 00 6c 00 53 00 74 00 72 00 75 00 63 00 22 00 20 00 26 00 20 00 22 00 74 00 43 00 72 00 65 00 61 00 74 00 65 00 28 00 [0-20] 28 00 22 00 22 00 63 00 7a 00 75 00 66 00 21 00 5c 00 22 00 22 00 29 00 20 00 26 00 20 00 42 00 69 00 6e 00 61 00 72 00 22 00 20 00 26 00 20 00 22 00 79 00 4c 00 65 00 6e 00}  //weight: 2, accuracy: Low
        $x_2_4 = {22 44 6c 6c 53 74 72 75 63 22 20 26 20 22 74 43 72 65 61 74 65 28 [0-20] 28 22 22 63 7a 75 66 21 5c 22 22 29 20 26 20 42 69 6e 61 72 22 20 26 20 22 79 4c 65 6e}  //weight: 2, accuracy: Low
        $x_1_5 = {26 00 3d 00 20 00 43 00 48 00 52 00 20 00 28 00 20 00 24 00 [0-20] 20 00 2d 00 20 00 28 00 20 00 31 00 20 00 5e 00 20 00 24 00 [0-20] 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {26 3d 20 43 48 52 20 28 20 24 [0-20] 20 2d 20 28 20 31 20 5e 20 24 [0-20] 20 29 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Autoitinject_PNPH_2147924760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.PNPH!MTB"
        threat_id = "2147924760"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "@Tem\" & \"pDir" ascii //weight: 2
        $x_2_2 = {22 00 44 00 6c 00 6c 00 22 00 20 00 26 00 20 00 22 00 43 00 61 00 6c 00 6c 00 28 00 [0-20] 28 00 22 00 22 00 6b 00 70 00 77 00 71 00 6f 00 65 00 70 00 77 00 71 00 6f 00 72 00 70 00 77 00 71 00 6f 00 6e 00 70 00 77 00 71 00 6f 00 65 00 70 00 77 00 71 00 6f 00 6c 00 70 00 77 00 71 00 6f 00 33 00 70 00 77 00 71 00 6f 00 32 00 70 00 77 00 71 00 6f 00 2e 00 70 00 77 00 71 00 6f 00 64 00 70 00 77 00 71 00 6f 00 6c 00 70 00 77 00 71 00 6f 00 6c 00 70 00 77 00 71 00 6f 00 22 00 22 00 29 00}  //weight: 2, accuracy: Low
        $x_2_3 = {22 44 6c 6c 22 20 26 20 22 43 61 6c 6c 28 [0-20] 28 22 22 6b 70 77 71 6f 65 70 77 71 6f 72 70 77 71 6f 6e 70 77 71 6f 65 70 77 71 6f 6c 70 77 71 6f 33 70 77 71 6f 32 70 77 71 6f 2e 70 77 71 6f 64 70 77 71 6f 6c 70 77 71 6f 6c 70 77 71 6f 22 22 29}  //weight: 2, accuracy: Low
        $x_1_4 = {22 00 44 00 6c 00 6c 00 22 00 20 00 26 00 20 00 22 00 43 00 61 00 6c 00 6c 00 28 00 [0-20] 28 00 22 00 22 00 75 00 70 00 77 00 71 00 6f 00 73 00 70 00 77 00 71 00 6f 00 65 00 70 00 77 00 71 00 6f 00 72 00 70 00 77 00 71 00 6f 00 33 00 70 00 77 00 71 00 6f 00 32 00 70 00 77 00 71 00 6f 00 2e 00 70 00 77 00 71 00 6f 00 64 00 70 00 77 00 71 00 6f 00 6c 00 70 00 77 00 71 00 6f 00 6c 00 70 00 77 00 71 00 6f 00 22 00 22 00 29 00}  //weight: 1, accuracy: Low
        $x_1_5 = {22 44 6c 6c 22 20 26 20 22 43 61 6c 6c 28 [0-20] 28 22 22 75 70 77 71 6f 73 70 77 71 6f 65 70 77 71 6f 72 70 77 71 6f 33 70 77 71 6f 32 70 77 71 6f 2e 70 77 71 6f 64 70 77 71 6f 6c 70 77 71 6f 6c 70 77 71 6f 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Autoitinject_PNQH_2147924867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.PNQH!MTB"
        threat_id = "2147924867"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {44 00 6c 00 6c 00 43 00 61 00 6c 00 6c 00 28 00 [0-20] 28 00 22 00 22 00 65 00 6b 00 6c 00 74 00 5f 00 72 00 2d 00 38 00 22 00 22 00 2c 00 20 00 36 00 29 00 2c 00 20 00 [0-20] 28 00 22 00 22 00 6a 00 7a 00 6c 00 22 00 22 00 2c 00 20 00 36 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {44 6c 6c 43 61 6c 6c 28 [0-20] 28 22 22 65 6b 6c 74 5f 72 2d 38 22 22 2c 20 36 29 2c 20 [0-20] 28 22 22 6a 7a 6c 22 22 2c 20 36 29}  //weight: 2, accuracy: Low
        $x_2_3 = {44 00 6c 00 6c 00 43 00 61 00 6c 00 6c 00 28 00 [0-20] 28 00 22 00 22 00 6f 00 79 00 5f 00 78 00 2d 00 38 00 22 00 22 00 2c 00 20 00 36 00 29 00 2c 00 20 00 [0-20] 28 00 22 00 22 00 66 00 78 00 5f 00 79 00 6f 00 72 00 6e 00 22 00 22 00 2c 00 20 00 36 00 29 00}  //weight: 2, accuracy: Low
        $x_2_4 = {44 6c 6c 43 61 6c 6c 28 [0-20] 28 22 22 6f 79 5f 78 2d 38 22 22 2c 20 36 29 2c 20 [0-20] 28 22 22 66 78 5f 79 6f 72 6e 22 22 2c 20 36 29}  //weight: 2, accuracy: Low
        $x_1_5 = {44 00 6c 00 6c 00 43 00 61 00 6c 00 6c 00 28 00 [0-20] 28 00 22 00 22 00 65 00 6b 00 6c 00 74 00 5f 00 72 00 2d 00 38 00 22 00 22 00 2c 00 20 00 36 00 29 00 2c 00 20 00 [0-20] 28 00 22 00 22 00 5e 00 7d 00 69 00 78 00 5e 00 22 00 22 00 2c 00 20 00 36 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {44 6c 6c 43 61 6c 6c 28 [0-20] 28 22 22 65 6b 6c 74 5f 72 2d 38 22 22 2c 20 36 29 2c 20 [0-20] 28 22 22 5e 7d 69 78 5e 22 22 2c 20 36 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Autoitinject_SZPJ_2147925513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.SZPJ!MTB"
        threat_id = "2147925513"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "k550060e550060r550060n550060e550060l55006035500602550060.550060d550060l550060l550060" ascii //weight: 4
        $x_3_2 = "u550060s550060e550060r55006035500602550060.550060d550060l550060l550060" ascii //weight: 3
        $x_1_3 = "DllCall" ascii //weight: 1
        $x_1_4 = "@TEMPDIR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Autoitinject_PMFH_2147925742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.PMFH!MTB"
        threat_id = "2147925742"
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
        $x_5_3 = "k52110e52110r52110n52110e52110l52110352110252110" ascii //weight: 5
        $x_7_4 = "u52110s52110e52110r52110352110252110" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

