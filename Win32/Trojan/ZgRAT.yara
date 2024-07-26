rule Trojan_Win32_ZgRAT_A_2147902541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZgRAT.A!MTB"
        threat_id = "2147902541"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 ad 66 83 f0 ?? 66 ab 66 83 f8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

