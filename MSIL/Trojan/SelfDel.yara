rule Trojan_MSIL_SelfDel_SG_2147904338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SelfDel.SG!MTB"
        threat_id = "2147904338"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SelfDel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "adsbc.exe" ascii //weight: 1
        $x_1_2 = "get_ExecutablePath" ascii //weight: 1
        $x_1_3 = "adsbc.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SelfDel_SGA_2147907025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SelfDel.SGA!MTB"
        threat_id = "2147907025"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SelfDel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/C ping 1.1.1.1 -n 2 -w 1000 > Nul & Del" wide //weight: 1
        $x_1_2 = "Klis.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

