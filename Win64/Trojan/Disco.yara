rule Trojan_Win64_Disco_CM_2147908976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Disco.CM!MTB"
        threat_id = "2147908976"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Disco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {30 4c 05 39 48 03 c7 48 83 f8 07 73 05 8a 4d 38 eb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

