rule Trojan_Win64_Wikiloader_XZ_2147902787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Wikiloader.XZ!MTB"
        threat_id = "2147902787"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Wikiloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 d9 48 c7 c0 2f 00 00 00 48 83 c0 31 65 48 8b 18 48 c7 c0 10 00 00 00 48 83 c0 08 50 48 31 c0 48 ff c0 48 85 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

