rule Trojan_MSIL_EfsPotato_VD_2147979471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/EfsPotato.VD!MTB"
        threat_id = "2147979471"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "EfsPotato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\\\localhost/PIPE/" ascii //weight: 2
        $x_2_2 = "EfsPotato" ascii //weight: 2
        $x_2_3 = "Encrypt" ascii //weight: 2
        $x_1_4 = "CreateProcessAsUser" ascii //weight: 1
        $x_1_5 = "Impersonate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

