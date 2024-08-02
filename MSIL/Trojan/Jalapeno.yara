rule Trojan_MSIL_Jalapeno_AJL_2147910601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.AJL!MTB"
        threat_id = "2147910601"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "46"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Steam Unlocker.exe" wide //weight: 10
        $x_10_2 = "0d4bf89c-3b30-4d70-bac8-5b9a0a979592" ascii //weight: 10
        $x_10_3 = "Daniel\\source\\repos\\Steam Unlocker\\Steam Unlocker\\obj\\Release\\Steam Unlocker.pdb" ascii //weight: 10
        $x_10_4 = "Trying elevate previleges to administrator" wide //weight: 10
        $x_5_5 = "http://adpk.duckdns.org:58630" wide //weight: 5
        $x_5_6 = "http://3.80.28.180/IwwpdjJD/chan.exe" wide //weight: 5
        $x_1_7 = "\\AppData\\Roaming\\Microsoft\\Windows\\FILE.exe" wide //weight: 1
        $x_1_8 = "\\AppData\\Roaming\\Microsoft\\Windows\\chan.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Jalapeno_OXAA_2147912526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.OXAA!MTB"
        threat_id = "2147912526"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {16 13 0a 2b 2b 11 05 11 0a 8f 29 00 00 01 25 47 08 d2 61 d2 52 11 0a 20 ff 00 00 00 5f 2d 0b 08 08 5a 20 b7 5c 8a 00 6a 5e 0c 11 0a 17 58 13 0a 11 0a 11 05 8e 69 32 cd}  //weight: 5, accuracy: High
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "ReverseDecode" ascii //weight: 1
        $x_1_4 = "Invoke" ascii //weight: 1
        $x_1_5 = "IsLogging" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_NE_2147913834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.NE!MTB"
        threat_id = "2147913834"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 00 95 11 05 13 05 61}  //weight: 5, accuracy: High
        $x_5_2 = {00 00 95 11 0f 13 0f 61}  //weight: 5, accuracy: High
        $x_5_3 = {95 11 0a 13 0a 61}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_SCAA_2147916554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.SCAA!MTB"
        threat_id = "2147916554"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 06 02 06 91 66 d2 9c 08}  //weight: 1, accuracy: High
        $x_2_2 = {02 06 8f 24 00 00 01 25 71 ?? 00 00 01 20 ?? 00 00 00 59 d2 81 ?? 00 00 01 08}  //weight: 2, accuracy: Low
        $x_2_3 = {02 06 8f 24 00 00 01 25 71 ?? 00 00 01 1f ?? 58 d2 81 ?? 00 00 01 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_SNAA_2147916916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.SNAA!MTB"
        threat_id = "2147916916"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 11 05 6f ?? 00 00 0a 11 05 20 00 01 00 00 5d d2 59 20 ff 00 00 00 5f d2 13 06 11 06 0f 02 28 ?? 00 00 0a 20 00 01 00 00 5d d2 61 d2 13 06 11 04 11 05 11 06 6f ?? 00 00 0a 00 00 11 05 17 58 13 05 11 05 11 04 6f ?? 00 00 0a fe 04 13 07 11 07 2d ab}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_NL_2147917177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.NL!MTB"
        threat_id = "2147917177"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {7e 02 00 00 04 7e ?? 00 00 04 6f ?? 00 00 0a 73 ?? 00 00 0a 25 72 ?? 00 00 70 6f ?? 00 00 0a 25 72 ?? 00 00 70 7e ?? 00 00 04 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 25}  //weight: 3, accuracy: Low
        $x_1_2 = "PorroQuisquamEst" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_SWAA_2147917323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.SWAA!MTB"
        threat_id = "2147917323"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {15 59 91 61 ?? 08 20 0d 02 00 00 58 20 0c 02 00 00 59 1d 59 1d 58 ?? 8e 69 5d 1f 09 58 1f 0c 58 1f 15 59 91 59 20 fb 00 00 00 58 1b 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_PPF_2147917642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.PPF!MTB"
        threat_id = "2147917642"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "cdn.gosth.ltd/launcher.exe" wide //weight: 2
        $x_2_2 = "Temp\\eu.png" wide //weight: 2
        $x_1_3 = "Gosth Injected!" wide //weight: 1
        $x_1_4 = "all traces destroyed!" wide //weight: 1
        $x_1_5 = "Self Delete" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

