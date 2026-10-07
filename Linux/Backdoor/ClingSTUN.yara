rule Backdoor_Linux_ClingSTUN_DA_2147979781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/ClingSTUN.DA!MTB"
        threat_id = "2147979781"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "ClingSTUN"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "me2=00%%3A00-00%%3A00&mac=%%3Bcd%%24%%7BIFS%%7D%%2Ftmp%%3Brm%%24%%7BIFS%%7D-rf%%24%%7BIFS%%7Dwget.sh%%3Bwget%%24%%7BIFS%%7Dhttp%%3A%%2F%%2F%u" ascii //weight: 10
        $x_10_2 = {69 6e 2f 2e 63 6c 69 6e 67 00 63 68 6d 6f 64 20 2b 78 20 2f 72 6f 6f 74 2f 2e 63 6c 69 6e 67 00 2f 65 74 63 2f 69 6e 69 74 74 61 62 00 2f 65 74 63 2f 69 6e 69 74 2e 64 2f 72 63 53 00 2f 65 74 63 2f 72 63 2e 64 2f 72 63 2e 62 6f 6f 74 00 00 00 63 68 6d 6f 64 20 2b 78 20 2f 75 73 72 2f 6c 6f 63 61 6c 2f 62 69 6e 2f 2e 63 6c 69 6e 67 00 00 65 63 68}  //weight: 10, accuracy: High
        $x_10_3 = {39 2e 32 31 32 00 00 00 36 36 2e 35 31 2e 31 32 38 2e 31 31 00 00 00 00 31 35 34 2e 37 33 2e 33 34 2e 38 00 31 38 35 2e 31 32 35 2e 31 38 30 2e 37 30 00 00 63 70 20 25 73 20 25 73 00 2f 64 65 76 2f 6e 75 6c 6c 00 00}  //weight: 10, accuracy: High
        $x_10_4 = {37 37 2e 37 32 2e 31 36 39 2e 32 31 32 00 00 00 36 36 2e 35 31 2e 31 32 38 2e 31 31 00 00 00 00 31 35 34 2e 37 33 2e 33 34 2e 38 00 31 38 35 2e 31 32 35 2e 31 38 30 2e 37 30 00 00 63 70 20 25}  //weight: 10, accuracy: High
        $x_10_5 = {6e 6f 77 6e 00 2f 64 65 76 2f 77 61 74 63 68 64 6f 67 00 00 00 2f 64 65 76 2f 6d 69 73 63 2f 77 61 74 63 68 64 6f 67 00 00 2f 70 72 6f 63 2f 73 65 6c 66 2f 65 78 65 00 00 2f 72 6f 6f 74 2f 2e 63 6c}  //weight: 10, accuracy: High
        $x_10_6 = {49 00 1e 15 bf 27 99 a8 16 00 54 56 a7 24 d3 e0 0e 37 7f 3e 82 78 06 ee b0 f8 7b 8c 00 54 56 a7 24 d3 e0 0e 37 7f 3e 8c 7e 06 ee b0 f8 7b 8c 00 09 4b f5 66 c2 a9 5d 77 60 63 c0 61 49 a6 9c ab 3d 90 28 8f 0f 6e 46 7d 00 0b 0a b7 39 91 00 09 4e f4 7b 8e ea 41 71 6d 69 c0 6c 4f a5 ec f6 3d 93 33 84 37 00 45 53 ea 66 c5 a6 05 6a 2c 2a 9d 61 49 bf ec f6 3d 93 33 84 37 00}  //weight: 10, accuracy: High
        $x_10_7 = {2f 76 cd 76 69 34 23 f9 3a 67 7c b5 c2 7c b1 bc 0d 84 14 71 7c 73 19 a5 41 29 b6 59 6f 76 b9 00 f7 fa 1c ac 2f 72 09 b6 42 db 24 1d 4c e0 85 66 fe c0 cf 74 a5 06 30 25 3c 22 45 00 17 0f b2 27 93 b2 17 3c 3d 34 da 20 17 f3 f7 00 1e 0e a9 38 96 a8 16 2a 22 34 d9 3a 00 11 0c a9 3e 93 a8 1f 24 35 2b dd 3f 15 00 11 0c a9 3e 93 a8 1f 24 35 2b dd 3f 17 00 13}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

