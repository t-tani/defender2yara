rule Trojan_MSIL_Athena_AC_2147979512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Athena.AC!MTB"
        threat_id = "2147979512"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Athena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "get_tasking" wide //weight: 2
        $x_2_2 = "rportfwd" wide //weight: 2
        $x_2_3 = "checkin" wide //weight: 2
        $x_2_4 = "Plugin not found. Please load it." wide //weight: 2
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

