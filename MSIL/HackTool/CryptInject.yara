rule HackTool_MSIL_CryptInject_NIT_2147924133_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/CryptInject.NIT!MTB"
        threat_id = "2147924133"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0d 00 02 28 ?? 00 00 06 13 04 09 11 04 16 11 04 8e 69 6f ?? 00 00 0a 00 09 6f ?? 00 00 0a 00 07 6f ?? 00 00 0a 13 05 28 ?? 00 00 0a 11 05 16 11 05 8e 69 6f ?? 00 00 0a 13 06 de 21}  //weight: 2, accuracy: Low
        $x_2_2 = {07 08 18 5b 02 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 08 18 58 0c 08 06 fe 04 0d 09 2d e0}  //weight: 2, accuracy: Low
        $x_2_3 = "\\obj\\Debug\\Loader.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

