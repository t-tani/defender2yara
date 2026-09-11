rule Ransom_MSIL_NineEtCrypt_PA_2147978093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/NineEtCrypt.PA!MTB"
        threat_id = "2147978093"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NineEtCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "9etVirus" ascii //weight: 3
        $x_1_2 = "DisableTaskMgr" wide //weight: 1
        $x_1_3 = "9et hacked your PC" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

