rule Trojan_MSIL_Xworm_NEAA_2147844429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xworm.NEAA!MTB"
        threat_id = "2147844429"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xworm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "$82ff5e55-94f0-4530-b928-7deaba1cdf37" ascii //weight: 5
        $x_1_2 = "get_HardwareLock_BIOS" ascii //weight: 1
        $x_1_3 = "GetProcessesByName" ascii //weight: 1
        $x_1_4 = "IntelliLock.Licensing" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xworm_NEAB_2147844543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xworm.NEAB!MTB"
        threat_id = "2147844543"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xworm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 11 01 28 0d 00 00 06 13 03 38 18 00 00 00 28 ?? 00 00 0a 11 00 28 13 00 00 06 28 ?? 00 00 0a 13 01}  //weight: 10, accuracy: Low
        $x_1_2 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_3 = "secondopen" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xworm_KAD_2147905524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xworm.KAD!MTB"
        threat_id = "2147905524"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xworm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "nc.bmexcellentfocus" ascii //weight: 2
        $x_2_2 = "SecurityHealth.bin" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xworm_KAE_2147910953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xworm.KAE!MTB"
        threat_id = "2147910953"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xworm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5f 63 13 04 08 11 04 60 d2 0c 07 11 05 25 20 01 00 00 00 58 13 05 08 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

