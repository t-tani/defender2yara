rule Trojan_MSIL_ShellCodeRunner_CXF_2147851161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShellCodeRunner.CXF!MTB"
        threat_id = "2147851161"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 09 11 10 11 08 11 10 9a 1f 10 28 ?? ?? ?? ?? 9c 00 11 10 17 58 13 10 11 10 11 08 8e 69 fe 04 13 11 11 11 2d d9}  //weight: 1, accuracy: Low
        $x_1_2 = "zhwgPHQExloaaD" ascii //weight: 1
        $x_1_3 = "xqMvSkuiE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ShellCodeRunner_GP_2147891923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShellCodeRunner.GP!MTB"
        threat_id = "2147891923"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {00 06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0c 08 2d e1}  //weight: 4, accuracy: High
        $x_1_2 = "The program is designed to perform process injection" wide //weight: 1
        $x_1_3 = "CreateRemoteThread Injection" wide //weight: 1
        $x_1_4 = "DLL Injection" wide //weight: 1
        $x_1_5 = "Process Hollowing" wide //weight: 1
        $x_1_6 = "APC Queue Injection" wide //weight: 1
        $x_1_7 = "XOR Encryption" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ShellCodeRunner_NR_2147917706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShellCodeRunner.NR!MTB"
        threat_id = "2147917706"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 06 11 05 09 11 04 6f ?? 00 00 0a 16 73 ?? 00 00 0a 13 07 16 fe 0e ee 01}  //weight: 3, accuracy: Low
        $x_1_2 = "RVirus.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

