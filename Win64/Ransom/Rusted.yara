rule Ransom_Win64_Rusted_ARA_2147979741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Rusted.ARA!MTB"
        threat_id = "2147979741"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Rusted"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {48 39 c3 74 10 8a 8c 05 90 02 00 00 41 30 0c 06 48 ff c0 eb eb}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

