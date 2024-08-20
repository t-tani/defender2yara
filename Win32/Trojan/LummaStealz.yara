rule Trojan_Win32_LummaStealz_B_2147919034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealz.B!MTB"
        threat_id = "2147919034"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lid=%s&j=%s&ver=" ascii //weight: 1
        $x_1_2 = {38 39 ca 83 e2 03 8a 54 14 08 32 54 0d 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

