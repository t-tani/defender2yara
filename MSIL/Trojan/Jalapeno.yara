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
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Tilesetter 2024" wide //weight: 1
        $x_2_2 = "20F3B949-149A-4515-B752-5497C04E16D4" ascii //weight: 2
        $x_5_3 = "Burstein.dll" wide //weight: 5
        $x_5_4 = "Burstein Applebee" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_AJL_2147910601_1
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

rule Trojan_MSIL_Jalapeno_NL_2147917177_1
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
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {02 7b bc 01 00 04 1c 8d 78 00 00 01 25 16 02 7c b8 00 00 04 28 57 00 00 0a a2 25 17 72 95 32 00 70 a2 25 18 02 7c b6 00 00 04 28 57 00 00 0a a2 25 19 72 a7 32 00 70 a2 25 1a 02 7c b7 00 00 04 28 57 00 00 0a a2 25 1b 72 ab 32 00 70 a2 28 5e 00 00 0a 6f 2a 00 00 0a}  //weight: 3, accuracy: High
        $x_1_2 = "done_droped" wide //weight: 1
        $x_1_3 = "eDba.exe" ascii //weight: 1
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

rule Trojan_MSIL_Jalapeno_PPF_2147917736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.PPF!MTB"
        threat_id = "2147917736"
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

rule Trojan_MSIL_Jalapeno_PJ_2147917932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.PJ!MTB"
        threat_id = "2147917932"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 5a 03 00 0a 0d 08 6f ?? ?? ?? 0a 16 09 a2 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 13 04 06 7e 4a 01 00 04 11 04 08 6f ?? ?? ?? 0a 08 2c 06}  //weight: 2, accuracy: Low
        $x_2_2 = {7e 4a 01 00 04 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 26 7e 4c 01 00 04 28 ?? ?? ?? 0a de 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_NJ_2147917953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.NJ!MTB"
        threat_id = "2147917953"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {28 fb 03 00 0a 6f fc 03 00 0a 28 fd 03 00 0a 28 fe 03 00 0a 28 07 00 00 2b 17 fe 02 0a 06}  //weight: 3, accuracy: High
        $x_1_2 = "SuDungSoLuong" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_TMAA_2147917980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.TMAA!MTB"
        threat_id = "2147917980"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 59 91 61 ?? 08 20 0d 02 00 00 58 20 0c 02 00 00 59 1d 59 1d 58 ?? 8e 69 5d 1f 09 58 1f 0c 58 1f 15 59 91 59 20 fb 00 00 00 58 1b 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_BZ_2147918059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.BZ!MTB"
        threat_id = "2147918059"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CryptedFile.exe" ascii //weight: 1
        $x_1_2 = "Soraadd.Resources" ascii //weight: 1
        $x_1_3 = "SoraAdd.exe" ascii //weight: 1
        $x_1_4 = "36537493-e85c-4d7e-96bc-32c472e96b4c" ascii //weight: 1
        $x_1_5 = "7c23ff90-33af-11d3-95da-00a024a85b51" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_NF_2147919249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.NF!MTB"
        threat_id = "2147919249"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {02 6f 0f 00 00 0a 0a 20 5e 1d 44 4c 03 58 20 24 00 00 00 d3}  //weight: 3, accuracy: High
        $x_2_2 = {5f 07 25 17 58 0b 61 d2 0d 25 1e 63 07 25 17 58 0b 61 d2}  //weight: 2, accuracy: High
        $x_1_3 = "ContainsKey" ascii //weight: 1
        $x_1_4 = "49CC6B38-355C-4F68-BFDC-1205742F5A93" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_ULAA_2147919544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.ULAA!MTB"
        threat_id = "2147919544"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {59 91 61 04 08 20 0c 02 00 00 58 20 0b 02 00 00 59 1b 59 1b 58 04 8e 69 5d 1f 09 58 1f 0d 58 1f 16 59 91 59 20 fb 00 00 00 58 1b 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_UTAA_2147919833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.UTAA!MTB"
        threat_id = "2147919833"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {59 91 61 03 08 20 0c 02 00 00 58 20 0b 02 00 00 59 1b 59 1b 58 03 8e 69 5d 1f 09 58 1f 0d 58 1f 16 59 91 59 20 fb 00 00 00 58 1b 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_VEAA_2147920050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.VEAA!MTB"
        threat_id = "2147920050"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b 1b 12 05 2b 1b 08 07 09 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a de 1d 11 04 2b e1 28 ?? 00 00 0a 2b de 1e 2c 0b 11 05 2c 07 11 04 28 ?? 00 00 0a 1c 2c f6 dc 17 2c bd 09 18 25 2c 09 58 0d 09 07 6f ?? 00 00 0a 3f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_XMAA_2147921703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.XMAA!MTB"
        threat_id = "2147921703"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 05 2a 00 11 00 72 97 00 00 70 28 ?? 00 00 06 72 c9 00 00 70 28 ?? 00 00 06 28 ?? 00 00 06 13 09 20 01 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 3a ?? 00 00 00 26}  //weight: 3, accuracy: Low
        $x_2_2 = {11 03 11 07 16 11 07 8e 69 28 ?? 00 00 06 20}  //weight: 2, accuracy: Low
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "GetByteArrayAsync" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_XRAA_2147921705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.XRAA!MTB"
        threat_id = "2147921705"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {16 13 04 2b 28 08 11 04 02 11 04 91 07 61 06 09 91 61 d2 9c 09 03 6f ?? 00 00 0a 17 59 33 04 16 0d 2b 04 09 17 58 0d 11 04 17 58 13 04 11 04 02 8e 69 32 d1}  //weight: 3, accuracy: Low
        $x_2_2 = {02 02 8e 69 17 59 91 1f 70 61 0b 02 8e 69 8d ?? 00 00 01 0c 16 0d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_SK_2147921710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.SK!MTB"
        threat_id = "2147921710"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 72 15 00 00 70 6f 29 00 00 0a 0a dd 0d 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_SARA_2147921756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.SARA!MTB"
        threat_id = "2147921756"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {d1 13 14 11 1d 11 09 91 13 22 11 1d 11 09 11 22 11 21 61 11 1f 19 58 61 11 34 61 d2 9c}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_AMB_2147921788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.AMB!MTB"
        threat_id = "2147921788"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0c 08 06 07 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 09 17 73 ?? 00 00 0a 13 05 11 05 02 16 02 8e 69 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 10 00 dd ?? 00 00 00 11 05 39 ?? 00 00 00 11 05 6f ?? 00 00 0a dc 11 04 39}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_VV_2147921878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.VV!MTB"
        threat_id = "2147921878"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 33 00 00 0a 80 01 00 00 04 73 34 00 00 0a 80 02 00 00 04 73 35 00 00 0a 80 03 00 00 04 73 35 00 00 0a 80 04 00 00 04 7e 03 00 00 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_MBXT_2147922236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.MBXT!MTB"
        threat_id = "2147922236"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {32 31 37 44 31 35 00 34 35 42 37 37 43 31 38 00 46 30 33 46 35 30}  //weight: 2, accuracy: High
        $x_1_2 = "16B7C39A.resources" ascii //weight: 1
        $x_1_3 = "unknownspf_loader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_YJAA_2147922431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.YJAA!MTB"
        threat_id = "2147922431"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 05 11 04 1f 10 6f ?? 01 00 0a 6f ?? 01 00 0a 00 11 05 11 05 6f ?? 01 00 0a 11 05 6f ?? 01 00 0a 6f ?? 01 00 0a 13 06 11 06 02 74 ?? 00 00 1b 16 02 14 72 1e 2c 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 01 00 0a 0b 07 74 ?? 00 00 1b 28 ?? 01 00 06 14 72 44 2c 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 74 ?? 00 00 1b 0a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

