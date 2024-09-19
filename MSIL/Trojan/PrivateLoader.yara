rule Trojan_MSIL_PrivateLoader_A_2147837874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PrivateLoader.A!MTB"
        threat_id = "2147837874"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PrivateLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 03 14 20 ?? 00 00 00 28 ?? 00 00 06 20 ?? 01 00 00 28 ?? 00 00 06 72 01 00 00 70 28 ?? 00 00 06 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 13 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PrivateLoader_B_2147849050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PrivateLoader.B!MTB"
        threat_id = "2147849050"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PrivateLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "creativelibamcreativelibsicreativelib.creativelibdcreativeliblcreativeliblcreativelib" wide //weight: 2
        $x_2_2 = "funfunAmfunfunsifunfunSfunfuncfunfunafunfunnBfunfunuffunfunfefunfunrfunfun" wide //weight: 2
        $x_2_3 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PrivateLoader_APL_2147892458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PrivateLoader.APL!MTB"
        threat_id = "2147892458"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PrivateLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 18 18 8c ?? 00 00 01 a2 25 19 18 8d 1f 00 00 01 25 17 18 8d 1f 00 00 01 25 16 11 06 a2 25 17 02 7b 1b 00 00 04 17 8d 1f 00 00 01 25 16 1c 8c ?? 00 00 01 a2 14}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PrivateLoader_SG_2147906259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PrivateLoader.SG!MTB"
        threat_id = "2147906259"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PrivateLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 13 0a 2b 33 11 08 11 0a 8f 1a 00 00 01 25 71 1a 00 00 01 08 d2 61 d2 81 1a 00 00 01 11 0a 20 ff 00 00 00 5f 2d 0b 08 08 5a 20 b7 5c 8a 00 6a 5e 0c 11 0a 17 58 13 0a 11 0a 11 08 8e 69 32 c5}  //weight: 1, accuracy: High
        $x_1_2 = "ScrubCrypt.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PrivateLoader_MBXQ_2147918551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PrivateLoader.MBXQ!MTB"
        threat_id = "2147918551"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PrivateLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bPkP1hYtjl.Fs5RDw4DygL" ascii //weight: 1
        $x_1_2 = {49 4d 4b 4a 58 45 00 41 4d 50 4b 43 51 4e 4e 45 41 58 56 42 50}  //weight: 1, accuracy: High
        $x_1_3 = "RJWxLgXCn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PrivateLoader_RDK_2147921404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PrivateLoader.RDK!MTB"
        threat_id = "2147921404"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PrivateLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 3d 00 00 0a 28 3e 00 00 0a 1a 8d 1e 00 00 01 25 16 28 3f 00 00 0a a2 25 17}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

