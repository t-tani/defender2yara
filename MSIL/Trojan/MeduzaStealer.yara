rule Trojan_MSIL_MeduzaStealer_AME_2147927861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MeduzaStealer.AME!MTB"
        threat_id = "2147927861"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MeduzaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 0a 06 28 39 00 00 0a 7d 1c 00 00 04 06 02 7d 1e 00 00 04 06 03 7d 1d 00 00 04 06 15 7d 1b 00 00 04 06 7c 1c 00 00 04 12 00 28 01 00 00 2b 06 7c 1c 00 00 04 28}  //weight: 2, accuracy: High
        $x_1_2 = {0a 00 06 02 7b 07 00 00 04 6f ?? 00 00 0a 00 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 73 42 00 00 0a 0c 08 07 17 73 43 00 00 0a 0d 09 73 44 00 00 0a 13 04 00 11 04 03 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

