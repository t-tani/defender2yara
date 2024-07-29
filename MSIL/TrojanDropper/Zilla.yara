rule TrojanDropper_MSIL_Zilla_MA_2147917203_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Zilla.MA!MTB"
        threat_id = "2147917203"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 02 6f 12 00 00 0a 0c de 0a}  //weight: 1, accuracy: High
        $x_1_2 = "stage2.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

