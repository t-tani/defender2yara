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

rule Trojan_Win32_Autoitinject_PPH_2147921553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.PPH!MTB"
        threat_id = "2147921553"
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

rule Trojan_Win32_Autoitinject_PPCH_2147921555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.PPCH!MTB"
        threat_id = "2147921555"
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

rule Trojan_Win32_Autoitinject_PPEH_2147921557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.PPEH!MTB"
        threat_id = "2147921557"
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

