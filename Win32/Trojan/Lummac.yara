rule Trojan_Win32_Lummac_GA_2147916810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lummac.GA!MTB"
        threat_id = "2147916810"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lummac"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ce 31 c4 cf c7 40 ?? 3a cd fe cb c7 40 ?? 36 c9 3c c7 c7 40 ?? 32 c5 c4 c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

