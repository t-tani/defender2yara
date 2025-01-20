rule Ransom_Linux_GonnaCry_A_2147795814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/GonnaCry.A!MTB"
        threat_id = "2147795814"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "GonnaCry"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Sup brother, all your files below have been encrypted, cheers!" ascii //weight: 2
        $x_1_2 = "KEY = %s IV = %s PATH = %s" ascii //weight: 1
        $x_1_3 = "/home/tarcisio/tests/" ascii //weight: 1
        $x_1_4 = "zip backup" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_GonnaCry_B_2147796723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/GonnaCry.B!MTB"
        threat_id = "2147796723"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "GonnaCry"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gona to delete file %s" ascii //weight: 1
        $x_1_2 = "rsa_crpt.c" ascii //weight: 1
        $x_1_3 = "/tmp/GNNCRY_Readme.txt!" ascii //weight: 1
        $x_1_4 = "we have done encrypt!" ascii //weight: 1
        $x_1_5 = "decrypt all file ,ssid:%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_GonnaCry_D_2147931052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/GonnaCry.D!MTB"
        threat_id = "2147931052"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "GonnaCry"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gonnacry" ascii //weight: 1
        $x_1_2 = "enc_files.gc" ascii //weight: 1
        $x_1_3 = "home/tarcisio/test" ascii //weight: 1
        $x_1_4 = "your_encrypted_files.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

