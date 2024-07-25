rule Ransom_Linux_Babuk_D_2147811833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Babuk.D!MTB"
        threat_id = "2147811833"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Babuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.decrypt_file" ascii //weight: 1
        $x_1_2 = "filepath.Walk" ascii //weight: 1
        $x_1_3 = "golang.org/x/crypto/chacha20" ascii //weight: 1
        $x_1_4 = "BABUK_LOCK" ascii //weight: 1
        $x_1_5 = "golang.org/x/crypto/curve25519" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Babuk_E_2147845996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Babuk.E!MTB"
        threat_id = "2147845996"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Babuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 8b 45 f0 48 83 c0 13 48 8d 15 aa ae 0b 00 48 89 d6 48 89 c7 e8 3c ef ff ff 85 c0 0f 84 fe 00 00 00 48 8b 45 f0 48 83 c0 13 48 8d 15 9b ae 0b 00 48 89 d6 48 89 c7 e8 9a ee ff ff 48 85 c0 0f 85 bd 00 00 00 8b 05 7b 07 0f 00 83 c0 01 89 05 72 07 0f 00 48 8b 55 c8 48 8b 45 d8 48 89 d6 48 89 c7 e8 af ed ff ff 48 8b 45 d8 48 89 c7 e8 43 ef ff ff 48 89 c2 48 8b 45 d8 48 01 d0 66 c7 00 2f 00 48 8b 45 f0 48 8d 50 13 48 8b 45 d8 48 89 d6 48 89 c7 e8 fd ed ff ff 48 8b 45 d8 48 89 c7 e8 11 ef ff ff 48 83 c0 01 48 89 c7 e8 e5 a6 02 00 48 89 45 f8 48 8b 55 d8 48 8b 45 f8 48 89 d6 48 89 c7 e8 4e ed ff ff 48 8b 45 f8 48 89 c6 48 8d 05 ff ad 0b 00 48 89 c7 b8 00 00 00 00}  //weight: 10, accuracy: High
        $x_1_2 = "/path/to/be/encrypted" ascii //weight: 1
        $x_1_3 = "bestway4u@mailfence.com" ascii //weight: 1
        $x_1_4 = "bestway4u@onionmail.com" ascii //weight: 1
        $x_1_5 = "Cylance Ransomware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Linux_Babuk_B_2147846672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Babuk.B!MTB"
        threat_id = "2147846672"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Babuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 73 61 67 65 3a 20 25 73 [0-7] 2f 74 6f 2f 62 65 2f 65 6e 63 [0-2] 79 70 74 65 64}  //weight: 1, accuracy: Low
        $x_1_2 = ".vmdk" ascii //weight: 1
        $x_1_3 = ".vswp" ascii //weight: 1
        $x_1_4 = "Encrypted files:" ascii //weight: 1
        $x_1_5 = "Skipped files:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Babuk_C_2147895099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Babuk.C!MTB"
        threat_id = "2147895099"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Babuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".x1nGx1nG" ascii //weight: 1
        $x_1_2 = "vim-cmd vmsvc/getallvms" ascii //weight: 1
        $x_1_3 = "kph29siuk8@skiff.com" ascii //weight: 1
        $x_1_4 = "vim-cmd vmsvc/power.shutdown %s" ascii //weight: 1
        $x_1_5 = "===[ To Restore Files ]===.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Babuk_F_2147901929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Babuk.F!MTB"
        threat_id = "2147901929"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Babuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d 05 4e b6 00 00 48 89 c7 e8 f6 f7 ff ff}  //weight: 1, accuracy: High
        $x_1_2 = "path/to/be/encrypted" ascii //weight: 1
        $x_1_3 = {48 8d 05 4a b6 00 00 48 89 c7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Babuk_G_2147904438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Babuk.G!MTB"
        threat_id = "2147904438"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Babuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All your files are encrypted" ascii //weight: 1
        $x_1_2 = "CYLANCE_README.txt" ascii //weight: 1
        $x_1_3 = "/path/to/be/encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Babuk_M_2147909482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Babuk.M"
        threat_id = "2147909482"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Babuk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Buongiorno la mia bella Italia" ascii //weight: 1
        $x_1_2 = "Welcome to the RansomHouse" ascii //weight: 1
        $x_1_3 = "You are locked by" ascii //weight: 1
        $x_1_4 = "W H I T E  R A B B I T" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Babuk_I_2147911020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Babuk.I!MTB"
        threat_id = "2147911020"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Babuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 2c 8b 45 0c 8b 55 f4 89 54 24 0c 89 44 24 08 c7 44 24 04 01 00 00 00 8b 45 08 89 04 24 e8 4f fe ff ff 8b 45 f4 89 04 24 e8 f4 fc ff ff c9}  //weight: 1, accuracy: High
        $x_1_2 = {55 89 e5 53 83 ec 34 8b 45 08 89 45 e0 8b 45 0c 89 45 e4 b8 14 00 00 00 89 04 24 e8 a2 fd ff ff 89 45 e8 c7 45 f0 00 00 00 00 c7 45 f4 00 00 00 10 c7 45 ec 00 00 00 00 e9 fd 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Babuk_PC_2147916874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Babuk.PC!MTB"
        threat_id = "2147916874"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Babuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".diskhelpyou" ascii //weight: 1
        $x_1_2 = "/How To Restore Your Files.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

