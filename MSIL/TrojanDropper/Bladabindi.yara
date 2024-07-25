rule TrojanDropper_MSIL_Bladabindi_AH_2147725844_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Bladabindi.AH!bit"
        threat_id = "2147725844"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 00 61 00 63 00 6b 00 65 00 64 00 00 ?? 74 00 68 00 65 00 64 00 61 00 79 00 73 00 2e}  //weight: 2, accuracy: Low
        $x_1_2 = "I.A.M.B.A.C.K" wide //weight: 1
        $x_1_3 = "SELECT * FROM AntivirusProduct" wide //weight: 1
        $x_2_4 = {5c 57 6f 72 6d (20|2d) 43 6c 69 65 6e 74 (20|2d) 4e 6f 72 6d 61 6c 44 6f 77 6e 6c 6f 61 64 65 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

