rule Trojan_Win64_OfferLoader_DA_2147980041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/OfferLoader.DA!MTB"
        threat_id = "2147980041"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "OfferLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {ce e8 fb a3 ff ff e9 ea 00 00 00 83 7b 0c 00 75 3b 8b 03 23 c1 3d 21 05 93 19 72 17 48 63 6b 20 85 ed 74 0f e8 60 a7 ff ff 48 03 c5 75 1e b9 ff ff ff 1f 8b 03 23 c1 3d 22 05 93 19 0f 82 b3 00 00 00 f6 43 24 04 0f 84 a9 00 00 00 81 3f 63 73 6d e0 75 68 83 7f 18 03 72 62 81 7f 20 22 05 93 19 76 59 48 8b 47 30 48 63 68 08 85 ed 74 4d e8 41 a7 ff ff 4c 8b d0 4c 03 d5 74 40 0f}  //weight: 10, accuracy: High
        $x_10_2 = {7d 08 49 83 c7 ec 66 0f 73 d8 08 66 48 0f 7e c0 48 c1 e8 20 48 8d 0c 80 48 8d 14 8a 4c 03 fa 4d 63 67 04 45 85 e4 74 25 e8 f8 9e ff ff 49 03 c4 74 1b 4d 63 67 04 45 85 e4 74 0a e8 e5 9e ff ff 49 03 c4 eb 02 33 c0 80 78 10 00 75 5d 41 f6 07 40 75 57 48 8b 84 24 38 01 00}  //weight: 10, accuracy: High
        $x_10_3 = {30 48 63 78 0c e8 d2 ad ff ff 48 83 c0 04 48 03 f8 48 8b 46 30 48 89 7c 24 68 48 63 58 0c e8 b9 ad ff ff 44 8b 3c 18 45 85 ff 7e 5a 48 63 c5 4c 8d 2c 80 48 63 37 e8 a1 ad ff ff 49 63 5e 04 48 03 f0 48 8b 44 24 60 48 8b 78 30 e8 60 ad ff ff 4c 8b c7 48 8b d6 4a 8d 0c}  //weight: 10, accuracy: High
        $x_10_4 = {06 80 74 0a 41 f6 06 10 0f 85 92 00 00 00 48 63 6e 04 85 ed 74 0b e8 f4 ab ff ff 48 8d 1c 28 eb 03 48 8b df e8 12 ac ff ff 49 63 4e 04 48 03 c8 48 3b d9 74 37 48 63 5e 04 85 db 74 0b e8 cd ab ff ff 48 8d 2c 03 eb 03 48 8b ef 49 63 5e 04 e8 e7 ab ff}  //weight: 10, accuracy: High
        $x_10_5 = {7b 4c 89 d0 e9 08 ff ff ff 40 80 e5 e0 40 80 fd a0 0f 85 80 00 00 00 eb 24 40 80 c5 70 40 80 fd 30 73 74 eb 38 44 8d 73 1f 41 80 fe 0c 72 08 80 e3 fe 80 fb ee 75 60 40 80 fd c0 7d 5a 4c 8d 70 02 4d 39 f0 76 4c 42 80 3c 32 bf 7f 4e eb 2d 80 c3 0f 80 fb 02 77 40 40 80 fd c0 7d 3a 48 8d 58 02 4c 39 c3 73 2c 80 3c 1a bf 7f 2f 4c 8d 70 03 4d 39 c6 73 1d 42 80 3c 32 bf 7f 23 49 ff c6 4c 89 f0 e9 8a fe ff ff 48 89 51 08 31 d2 4c 89 c0 eb 1b 45 31 d2 eb 0a b3 01 eb 06 b3 02 eb 02 b3 03 44 88}  //weight: 10, accuracy: High
        $x_10_6 = {e2 31 c0 eb 6e b0 21 eb 6a b0 26 eb 66 b0 04 eb 62 b0 05 eb 5e b0 1a eb 5a b0 0b eb 56 b0 18 eb 52 b0 14 eb 4e b0 0c eb 4a b0 1f eb 46 b0 11 eb 42 b0 03 eb 3e b0 02 eb 3a b0 07 eb 36 b0 09 eb 32 b0 06 eb 2e b0 0a eb 2a b0 24 eb 26 b0 20 eb 22 b0 12 eb 1e b0 0d eb 1a b0 10 eb 16 b0 1e eb 12 b0 19 eb 0e}  //weight: 10, accuracy: High
        $x_10_7 = {48 8d 53 f0 49 39 d7 77 2c 4f 8b 04 3e 4f 8b 4c 3e 08 49 89 ca 4d 29 c2 4d 09 c2 49 89 c8 4d 29 c8 4d 09 c8 49 21 c2 4d 21 c2 49 39 c2 75 06 49 83 c7 10 eb cf 4d 01 fe 4c 29 fb}  //weight: 10, accuracy: High
        $x_10_8 = {b6 1c 02 84 db 78 46 45 89 da 41 29 c2 41 f6 c2 07 74 09 48 ff c0 eb de 48 83 c0 10 49 39 c1 76 0e 4c 8b 54 02 08 4c 0b 14 02 49 85 fa 74 e9 49 39 c0 49 89 c2 4d 0f 47 d0 4c 39 c0 0f 83 a4 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

