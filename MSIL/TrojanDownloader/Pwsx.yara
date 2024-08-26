rule TrojanDownloader_MSIL_Pwsx_SM_2147852034_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Pwsx.SM!MTB"
        threat_id = "2147852034"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Pwsx"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 08 6f 8f 00 00 0a 5d 13 06 09 08 6f 8f 00 00 0a 5b 13 07 08 72 06 05 00 70 18 18 8d 1d 00 00 01 25 16 11 06 8c 3f 00 00 01 a2 25 17 11 07 8c 3f 00 00 01 a2 28 90 00 00 0a a5 2d 00 00 01 13 08 12 08 28 91 00 00 0a 13 09 07 11 09 6f 92 00 00 0a 09 17 58 0d 09 08 6f 8f 00 00 0a 08 6f 93 00 00 0a 5a 32 9a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Pwsx_SN_2147891704_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Pwsx.SN!MTB"
        threat_id = "2147891704"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Pwsx"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 11 04 5d 13 06 06 11 07 5d 13 0a 07 11 06 91 13 0b 11 05 11 0a 6f ?? ?? ?? 0a 13 0c 07 06 17 58 11 04 5d 91 13 0d 11 0b 11 0c 61 11 0d 59 20 00 01 00 00 58 13 0e 07 11 06 11 0e 20 00 01 00 00 5d d2 9c 06 17 59 0a 06 16 fe 04 16 fe 01 13 0f 11 0f 2d ab}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Pwsx_SO_2147891705_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Pwsx.SO!MTB"
        threat_id = "2147891705"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Pwsx"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 72 9f 00 00 70 6f 16 00 00 0a 6f 17 00 00 0a 6f 18 00 00 0a 6f 19 00 00 0a 6f 1a 00 00 0a 0a dd 0d 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Pwsx_SQ_2147900947_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Pwsx.SQ!MTB"
        threat_id = "2147900947"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Pwsx"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 20 00 01 00 00 13 06 11 05 17 58 13 07 11 05 20 00 3a 01 00 5d 13 08 11 07 20 00 3a 01 00 5d 13 09 07 11 09 91 11 06 58 13 0a 07 11 08 91 13 0b 08 11 05 1f 16 5d 91 13 0c 11 0b 11 0c 61 13 0d 07 11 08 11 0d 11 0a 59 11 06 5d d2 9c 00 11 05 17 58 13 05 11 05 20 00 3a 01 00 fe 04 13 0e 11 0e 2d 9c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Pwsx_SR_2147900948_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Pwsx.SR!MTB"
        threat_id = "2147900948"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Pwsx"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 20 00 01 00 00 13 07 11 06 17 58 13 08 11 06 20 00 58 01 00 5d 13 09 11 08 20 00 58 01 00 5d 13 0a 07 11 09 91 13 0b 08 11 06 1f 16 5d 91 13 0c 07 11 0a 91 11 07 58 13 0d 11 0b 11 0c 61 13 0e 11 0e 11 0d 59 13 0f 07 11 09 11 0f 11 07 5d d2 9c 00 11 06 17 58 13 06 11 06 20 00 58 01 00 fe 04 13 10 11 10 2d 98}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Pwsx_ST_2147906163_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Pwsx.ST!MTB"
        threat_id = "2147906163"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Pwsx"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 06 17 58 09 5d 91 13 0c 07 06 91 13 0d 08 06 08 6f 72 00 00 0a 5d 6f 73 00 00 0a 13 0e 11 0d 11 0e 61 11 0c 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 0f 07 06 11 0f d2 9c 06 17 58 0a 06 09 fe 04 13 10 11 10 2d b8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Pwsx_SV_2147917692_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Pwsx.SV!MTB"
        threat_id = "2147917692"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Pwsx"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 11 05 08 5d 08 58 08 5d 91 11 06 61 11 08 59 20 00 02 00 00 58 13 09 16 13 12}  //weight: 2, accuracy: High
        $x_1_2 = "RemoteWget.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Pwsx_SW_2147919614_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Pwsx.SW!MTB"
        threat_id = "2147919614"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Pwsx"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 6f 6b 00 00 0a 20 00 b8 00 00 2f 0d 08 12 08 28 6d 00 00 0a 6f 6a 00 00 0a 11 07 17 58 13 07 11 07 07 6f 6e 00 00 0a 32 a3}  //weight: 2, accuracy: High
        $x_2_2 = "Whisper.Properties.Resources.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

