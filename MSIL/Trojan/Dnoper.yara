rule Trojan_MSIL_Dnoper_R_2147831285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dnoper.R!MTB"
        threat_id = "2147831285"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dnoper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\&0zTU)R;50Y0mxXRfCd:\\+Hcw!.resources" ascii //weight: 2
        $x_2_2 = "PcKEHyOUPPVCqPaMIMwHjlNidrIR" ascii //weight: 2
        $x_2_3 = "4F89C700331F900C" wide //weight: 2
        $x_1_4 = "set_UseShellExecute" ascii //weight: 1
        $x_1_5 = "056ACA176CDC486F810AAF4F711D662C452E9760" ascii //weight: 1
        $x_1_6 = "$87b43f01-0b5e-49b6-8de4-7563e84fd71e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dnoper_AL_2147841498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dnoper.AL!MTB"
        threat_id = "2147841498"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dnoper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 27 00 00 70 0a 06 28 ?? ?? ?? 0a 0d 00 17 73 1d 00 00 0a 72 53 00 00 70 6f ?? ?? ?? 0a 13 04 09 11 04 16 11 04 8e 69 6f}  //weight: 2, accuracy: Low
        $x_1_2 = "PLUGG LOCK" wide //weight: 1
        $x_1_3 = "c:\\Windows\\module.bat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dnoper_EC_2147841684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dnoper.EC!MTB"
        threat_id = "2147841684"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dnoper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RPF:SmartAssembly" wide //weight: 1
        $x_1_2 = "System.Security.Cryptography.AesCryptoServiceProvider" wide //weight: 1
        $x_1_3 = "get_AllowOnlyFipsAlgorithms" ascii //weight: 1
        $x_1_4 = "WllKbiyDaV" ascii //weight: 1
        $x_1_5 = "oBNK1ENQdP" ascii //weight: 1
        $x_1_6 = "cJMKx1XxeW" ascii //weight: 1
        $x_1_7 = "AesCryptoServiceProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dnoper_CXRJK_2147847841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dnoper.CXRJK!MTB"
        threat_id = "2147847841"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dnoper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 28 1e 00 00 0a 0a 1f 1a 28 1f 00 00 0a 72 ?? d3 07 70 28 1d 00 00 0a 0c 08 06 28 20 00 00 0a 72 ?? d3 07 70 72 ?? d3 07 70 08 72 ?? d3 07 70 28 21 00 00 0a 28 22 00 00 0a 26 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dnoper_ADN_2147851655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dnoper.ADN!MTB"
        threat_id = "2147851655"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dnoper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a2 25 17 08 a2 25 18 72 e7 0e 00 70 a2 25 19 02 7b 12 00 00 04 a2 25 1a 72 17 0f 00 70 a2 28 28 00 00 0a 13 04 09 11 04 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dnoper_ADN_2147851655_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dnoper.ADN!MTB"
        threat_id = "2147851655"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dnoper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 00 16 28 ?? 00 00 0a 00 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 0a 06 28 ?? 00 00 06 28 ?? 00 00 0a 00 7e ?? 00 00 0a 72 ?? 00 00 70 17 6f ?? 00 00 0a 0b 00 07 72 ?? 00 00 70 06 6f ?? 00 00 0a 00 00 de 10 07 14 fe 01 0c 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dnoper_ADN_2147851655_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dnoper.ADN!MTB"
        threat_id = "2147851655"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dnoper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0b 07 72 21 9d 07 70 28 1d 00 00 0a 0b 07 72 ec 9d 07 70 28 1d 00 00 0a 0b 07 28 1e 00 00 0a 0a 1f 1a 28 1f 00 00 0a 72 9f 9e 07 70 28 1d 00 00 0a 0c 08 06}  //weight: 2, accuracy: High
        $x_1_2 = "SH FILE.exe" wide //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "GetFolderPath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dnoper_EM_2147894245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dnoper.EM!MTB"
        threat_id = "2147894245"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dnoper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Euauip1ldrbCyUfZfd.0Ph6TfqYcxPpt86GE9" wide //weight: 1
        $x_1_2 = "8UEo3HKscF4kJ9m7lV.A0FsXYFca1n4LihEVf" wide //weight: 1
        $x_1_3 = "kBwgXslK48GwUfcg7l.WGILrH9DHul1m935pV" wide //weight: 1
        $x_1_4 = "clrjit.dll" wide //weight: 1
        $x_1_5 = "SpotifyStartupTask" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dnoper_MBFG_2147897264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dnoper.MBFG!MTB"
        threat_id = "2147897264"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dnoper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 07 6f ?? 02 00 0a 17 73 c2 00 00 0a 25 02 16 02 8e 69 6f ?? 01 00 0a 6f ?? 01 00 0a 06}  //weight: 1, accuracy: Low
        $x_1_2 = {74 65 44 65 63 72 79 70 74 6f 72 00 65 58 5a 48 46 46 53 71 6e 63 00 6f 53 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dnoper_NA_2147903266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dnoper.NA!MTB"
        threat_id = "2147903266"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dnoper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 95 58 ?? ?? 08 00 04 0e 06 17 59 95 58 0e 05 28 e7 0d 00 06 58 54 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dnoper_NB_2147903267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dnoper.NB!MTB"
        threat_id = "2147903267"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dnoper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 95 58 7e b4 08 00 04 0e 06 17 59 95 58 0e 05 28 ?? 0d 00 06 58 54 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dnoper_NC_2147903268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dnoper.NC!MTB"
        threat_id = "2147903268"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dnoper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 95 58 7e a2 08 00 04 0e 06 17 59 95 58 0e 05 28 ?? 0d 00 06 58 54 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dnoper_NE_2147903269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dnoper.NE!MTB"
        threat_id = "2147903269"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dnoper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 95 58 7e ?? 08 00 04 0e 06 17 59 95 58 0e 05 28 e7 0d 00 06 58 54 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dnoper_NF_2147904306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dnoper.NF!MTB"
        threat_id = "2147904306"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dnoper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 95 58 7e ?? 08 00 04 0e 06 17 59 95 58 0e 05 28 c9 0d 00 06 58 54 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dnoper_NF_2147904306_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dnoper.NF!MTB"
        threat_id = "2147904306"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dnoper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 95 58 7e a3 08 00 04 0e 06 17 59 95 58 0e 05 28 ?? 0d 00 06 58 54 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dnoper_NG_2147906172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dnoper.NG!MTB"
        threat_id = "2147906172"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dnoper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {91 03 61 1f 1a 5f 9c 59}  //weight: 10, accuracy: High
        $x_1_2 = "DownloadFile" ascii //weight: 1
        $x_1_3 = "Decrypt" ascii //weight: 1
        $x_1_4 = "RijndaelManaged" ascii //weight: 1
        $x_1_5 = "Antivirus" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dnoper_NH_2147909512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dnoper.NH!MTB"
        threat_id = "2147909512"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dnoper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 95 58 7e ?? 08 00 04 0e 06 17 59 95 58 0e 05 28 d1 0d 00 06 58 54 2a}  //weight: 10, accuracy: Low
        $x_2_2 = "System.Security.Cryptography.AesCryptoServiceProvider" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dnoper_PAFS_2147922992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dnoper.PAFS!MTB"
        threat_id = "2147922992"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dnoper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "DoWhenEnteredEnCRYFolder" wide //weight: 1
        $x_1_2 = "/k systeminfo > \"" wide //weight: 1
        $x_1_3 = "DoWhenFinishedDECRYFolder" wide //weight: 1
        $x_1_4 = "DoWhenBackEnCRYFolder" wide //weight: 1
        $x_1_5 = "UseOutCryList" wide //weight: 1
        $x_1_6 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 [0-20] 5c 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 73 00 5c 00 [0-20] 2e 00 62 00 61 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dnoper_AMV_2147925328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dnoper.AMV!MTB"
        threat_id = "2147925328"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dnoper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 0d 09 6f ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 39 ?? 00 00 00 09 14 14 6f ?? 00 00 0a 26 08 17 58 0c 08 07 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

