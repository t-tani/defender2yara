rule Trojan_Win64_Nanocore_GPD_2147902561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Nanocore.GPD!MTB"
        threat_id = "2147902561"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {49 8b d1 80 32 ?? 41 ff c0 48 8d 52}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

