rule Trojan_Win64_ChromeExtractor_FG_2147977863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ChromeExtractor.FG!MTB"
        threat_id = "2147977863"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ChromeExtractor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 1f 80 f2 ?? 48 8d 8c 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 ff c3 48 83 fb ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

