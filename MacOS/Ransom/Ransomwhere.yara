rule Ransom_MacOS_Ransomwhere_A_2147923812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MacOS/Ransomwhere.A"
        threat_id = "2147923812"
        type = "Ransom"
        platform = "MacOS: "
        family = "Ransomwhere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "github.com/hazcod/ransomwhere" ascii //weight: 1
        $x_1_2 = "crypto.EncryptFile" ascii //weight: 1
        $x_1_3 = "file.WalkFiles" ascii //weight: 1
        $x_1_4 = "snapshots.WipeSnapshots" ascii //weight: 1
        $x_1_5 = "crypto.DecryptFile" ascii //weight: 1
        $x_1_6 = "AGE-SECRET-KEY-" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

