rule Trojan_MSIL_Hawkeye_DHB_2147748644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Hawkeye.DHB!MTB"
        threat_id = "2147748644"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hawkeye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 08 09 1b 5b 93 6f ?? ?? ?? ?? 1f 0a 62 13 04 09 1b 5b 17 58 08 8e 69 fe 04 13 05 11 05 2c 14 11 04 06 08 09 1b 5b 17 58 93 6f ?? ?? ?? ?? 1b 62 60 13 04 09 1b 5b 18 58}  //weight: 1, accuracy: Low
        $x_1_2 = {08 8e 69 fe 04 13 06 11 06 2c 12 11 04 06 08 09 1b 5b 18 58 93 6f ?? ?? ?? ?? 60 13 04 20 ff 00 00 00 11 04 1f 0f 09 1b 5d 59 1e 59 1f 1f 5f 63 5f 13 04 07 11 04 d2 6f ?? ?? ?? ?? 00 00 09 1e 58 0d 09 02 6f ?? ?? ?? ?? 1b 5a fe 04 13 07 11 07 3a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_Hawkeye_AFD_2147833489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Hawkeye.AFD!MTB"
        threat_id = "2147833489"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hawkeye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 11 04 08 11 04 9a 28 ?? ?? ?? 0a 9c 11 04 17 58 13 04 11 04 1f 18 32 e7}  //weight: 2, accuracy: Low
        $x_1_2 = "Split" ascii //weight: 1
        $x_1_3 = "GetTypeFromHandle" ascii //weight: 1
        $x_1_4 = "GetFields" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Hawkeye_AIOW_2147833823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Hawkeye.AIOW!MTB"
        threat_id = "2147833823"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hawkeye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 d6 13 04 11 04 16 28 ?? ?? ?? 06 7e 01 00 00 04 d8 fe 04 13 06 11 06 2c 0b 16}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Hawkeye_AHE_2147840878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Hawkeye.AHE!MTB"
        threat_id = "2147840878"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hawkeye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0c 0a 2b 37 02 50 06 02 50 8e b7 5d 02 50 06 02 50 8e b7 5d 91 03 06 03 8e b7 5d 91 61 02 50 06 17 d6 02 50 8e b7 5d 91 da 20 00 01 00 00 d6 20 00 01 00 00 5d b4 9c 06 17 d6 0a 06 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Hawkeye_AHE_2147840878_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Hawkeye.AHE!MTB"
        threat_id = "2147840878"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hawkeye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0b 2b 20 09 65 1a 5d 2c 11 28 ?? ?? ?? 06 8e 69 1b 59 17 58 8d 05 00 00 01 0c 09 17 58 0d 09 1f 64 31 c1}  //weight: 2, accuracy: Low
        $x_1_2 = "socruA.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Hawkeye_AHW_2147849316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Hawkeye.AHW!MTB"
        threat_id = "2147849316"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hawkeye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {7e 36 00 00 04 08 07 6f c3 00 00 0a 28 c5 00 00 0a 13 04 28 71 00 00 0a 11 04 16 11 04 8e 69 6f c3 00 00 0a 28 54 01 00 0a 13 05 7e 38 00 00 04 39 18 00 00 00 7e 37 00 00 04 02 11 05}  //weight: 2, accuracy: High
        $x_1_2 = "8d689f9b-f435-43e6-8f43-6e4eb6257f8e" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Hawkeye_AHY_2147918875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Hawkeye.AHY!MTB"
        threat_id = "2147918875"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hawkeye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 0a 2b 2b 16 0b 2b 13 02 06 02 06 91 7e 01 00 00 04 07 91 61 d2 9c 07 17 58 0b 07 7e 01 00 00 04 8e 69 fe 04 13 04 11 04 2d dd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

