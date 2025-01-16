rule Ransom_Linux_Lockbit_CD_2147930747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Lockbit.CD!MTB"
        threat_id = "2147930747"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Lockbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {58 46 b9 6b fe f7 c6 ec df f8 a0 c3 d7 e9 0e 01 dc e9 00 23 10 eb 02 0b 41 eb 03 0e 5a 46 73 46 cc e9 00 23 b8 f1 00 0f 02 d0 40 46 fe f7 16 eb}  //weight: 1, accuracy: High
        $x_1_2 = {74 49 07 f5 dc 6a d1 e9 02 23 54 1c 43 f1 00 05 d1 e9 04 23 c1 e9 02 45 da e9 00 45 a4 18 45 eb 03 09 22 46 4b 46 c1 e9 04 23}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

