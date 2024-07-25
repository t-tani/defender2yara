rule Ransom_Linux_Akira_A_2147851013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Akira.A!MTB"
        threat_id = "2147851013"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Akira"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "akira_readme.txt" ascii //weight: 1
        $x_1_2 = "--encryption_path" ascii //weight: 1
        $x_1_3 = "--share_file" ascii //weight: 1
        $x_1_4 = ".akira" ascii //weight: 1
        $x_1_5 = "--encryption_percent" ascii //weight: 1
        $x_1_6 = {74 74 70 73 3a 2f 2f [0-88] 2e 6f 6e 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Akira_B_2147891813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Akira.B!MTB"
        threat_id = "2147891813"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Akira"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "akiralkzxzq2dsrzsrvbr2xgbbu2wgsmxryd4csgfameg52n7efvr2id.onion." ascii //weight: 5
        $x_1_2 = "--encryption_path" ascii //weight: 1
        $x_1_3 = "--encryption_percent" ascii //weight: 1
        $x_1_4 = ".akira" ascii //weight: 1
        $x_1_5 = "akira_readme.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

