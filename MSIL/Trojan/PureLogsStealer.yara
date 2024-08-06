rule Trojan_MSIL_PureLogsStealer_APL_2147899424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogsStealer.APL!MTB"
        threat_id = "2147899424"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogsStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 07 11 06 11 07 16 1a 6f ?? 00 00 0a 26 11 07 16 28 ?? 00 00 0a 13 08 11 06 16 73 ?? 00 00 0a 13 09 11 09 08 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogsStealer_APL_2147899424_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogsStealer.APL!MTB"
        threat_id = "2147899424"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogsStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 25 17 6f ?? 00 00 0a 00 25 16 6f ?? 00 00 0a 00 0c 08 6f ?? 00 00 0a 72 ?? 05 00 70 6f ?? 00 00 0a 26 08 6f}  //weight: 2, accuracy: Low
        $x_1_2 = "\\AppData\\Local\\Temporary Projects\\WindowsFormsApp1\\obj\\Debug\\iTalk.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogsStealer_A_2147907671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogsStealer.A!MTB"
        threat_id = "2147907671"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogsStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 70 20 00 01 00 00 14 14 14 6f ?? 00 00 0a 6f ?? 00 00 0a 2a}  //weight: 2, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogsStealer_B_2147907965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogsStealer.B!MTB"
        threat_id = "2147907965"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogsStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 00 11 06 28 ?? 00 00 2b 28 ?? 00 00 2b 16 11 06 8e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

