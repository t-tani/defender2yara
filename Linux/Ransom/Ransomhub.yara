rule Ransom_Linux_Ransomhub_A_2147910974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Ransomhub.A"
        threat_id = "2147910974"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Ransomhub"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "please wait for the single file encryption to complete" ascii //weight: 1
        $x_1_2 = "unable to encrypt file %s, the file may be empty" ascii //weight: 1
        $x_1_3 = "missing value for -pass" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

