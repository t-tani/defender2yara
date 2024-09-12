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

