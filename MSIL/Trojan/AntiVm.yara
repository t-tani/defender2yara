rule Trojan_MSIL_AntiVm_NA_2147906969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AntiVm.NA!MTB"
        threat_id = "2147906969"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AntiVm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {06 02 07 6f 7c 00 00 0a 03 07 6f 7c 00 00 0a 61 60 0a 07 17 58 0b 07 02 6f 15 00 00 0a 32 e1}  //weight: 10, accuracy: High
        $x_1_2 = "drivers\\vmmouse.sys" ascii //weight: 1
        $x_1_3 = "drivers\\vmhgfs.sys" ascii //weight: 1
        $x_1_4 = "taskkill /f /im OllyDbg.exe" ascii //weight: 1
        $x_1_5 = "sc stop wireshark" ascii //weight: 1
        $x_1_6 = "taskkill /f /im HTTPDebugger.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

