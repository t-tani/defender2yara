rule Trojan_MSIL_Reomot_KK_2147979617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Reomot.KK!MTB"
        threat_id = "2147979617"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Reomot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {11 15 11 16 9a 13 0a 11 0a 03 28 07 00 00 06 11 16 17 58 13 16 11 16 11 15 8e 69 32 e3}  //weight: 20, accuracy: High
        $x_10_2 = "Unable to get Browser Credentials in Windows 11" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

