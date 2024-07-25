rule Trojan_MSIL_Crypter_X_2147759492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crypter.X!MTB"
        threat_id = "2147759492"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 00 00 11 00 28 ?? 00 00 0a 7e 03 00 00 04 28 18 00 00 06 74 01 00 00 1b 0a 28 17 00 00 06 26 28 16 00 00 06 16 fe 01 0d 09 2d 02 16 0b 16 0b 2b ?? 00 02 07 8f ?? 00 00 01 25 71 ?? 00 00 01 06 07 00}  //weight: 5, accuracy: Low
        $x_2_2 = "Xeger" ascii //weight: 2
        $x_2_3 = "Fare" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

