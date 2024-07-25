rule Ransom_MSIL_Phobos_PA_2147793989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Phobos.PA!MTB"
        threat_id = "2147793989"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Phobos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "!README!.hta" wide //weight: 1
        $x_1_2 = "Shadowofdeath" wide //weight: 1
        $x_1_3 = "All your files have been encrypted!" wide //weight: 1
        $x_1_4 = "wbadmin delete systemstatebackup -deleteoldest" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

