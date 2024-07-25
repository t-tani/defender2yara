rule Trojan_MSIL_CryptMiner_NZK_2147836917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptMiner.NZK!MTB"
        threat_id = "2147836917"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "transfer.sh/get/" wide //weight: 3
        $x_3_2 = "afa8-3a9d4430dcc1" ascii //weight: 3
        $x_3_3 = {55 02 c0 09 00 00 00 00 fa 25 33 00 16 00 00 01}  //weight: 3, accuracy: High
        $x_1_4 = "DecodingBytes" ascii //weight: 1
        $x_1_5 = "Download" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

