rule Trojan_MSIL_SilentCryptoMiner_2147893045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SilentCryptoMiner!rootkit"
        threat_id = "2147893045"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SilentCryptoMiner"
        severity = "Critical"
        info = "rootkit: rootkit component of that malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {13 0b 11 0a 11 06 28 10 00 00 06 26 11 0a 11 06 07 6a 20 00 30 00 00 1f 40 28 0e 00 00 06 26 11 0a 11 06 02 08 16 6a 28 0f 00 00 06 26 16}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

