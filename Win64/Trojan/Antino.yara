rule Trojan_Win64_Antino_DA_2147979663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Antino.DA!MTB"
        threat_id = "2147979663"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Antino"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {61 e1 3e 8e 0f b2 3e 8e 0f b2 3e 8e 0f b2 47 0f 0c b3 0b 8e 0f b2 47 0f 0a b3 b3 8e 0f b2 47 0f 0b b3 1c 8e 0f b2 b9 07 0c b3 2a 8e 0f b2 b9 07 0b b3 2f 8e 0f b2 b9 07 0a b3 19 8e 0f b2 47 0f 0e b3 3a 8e 0f b2 3e 8e 0e b2 d4 8e 0f b2 3e 8e 0f b2 27 8e 0f b2 a8 07 f0 b2 3f 8e 0f b2 a8 07}  //weight: 10, accuracy: High
        $x_10_2 = {49 df c7 e0 f9 d0 16 a5 eb 70 a2 7f a7 8c 62 ab 57 fc 45 46 c5 33 7a d6 82 6e 9e 37 b1 cb bb 8f a0 ea d7 4a fc 31 f7 89 7e 05 de c0 71 99 f5 5d 22 c0 5d 6a c2 08 34 e6 71 ff 6e 33 a4 fa 03 1a c0 f1 97 75 27 26 ce 8b b3 e0 48 3e 76 96 a5 bd a0 54 71 53 e5}  //weight: 10, accuracy: High
        $x_10_3 = {86 da ff e0 86 da ff e0 86 da ff e0 86 da ff e0 86 da ff e0 86 da ff e0 86 da ff e0 86 da ff e0 86 da ff e0 86 da ff 23 87 da ff e0 86 da ff e0 86 da ff e0 86 da ff e0 86 da ff e0 86 da ff e0 86 da ff e0 86 da ff b7 87 da ff e0 86 da ff e0 86 da ff e0 86 da ff e0 86 da ff e0 86 da ff 5c 88 da ff e0 86 da ff e0 86 da ff e0 86 da ff e0 86 da ff e0 86 da ff e0}  //weight: 10, accuracy: High
        $x_10_4 = {22 17 d8 ff 22 17 d8 ff 44 14 d8 ff 1a 13 d8 ff 45 15 d8 ff 66 15 d8 ff a9 13 d8 ff 43 14 d8 ff 43 14 d8 ff 43 14 d8 ff 43 14 d8 ff 43 14 d8 ff 43 14 d8 ff 43 14 d8 ff 43 14 d8 ff 43 14 d8 ff 43 14 d8 ff}  //weight: 10, accuracy: High
        $x_10_5 = {47 49 cf c2 ad 18 39 c8 f7 82 d6 09 f9 6c 54 5f 5b 86 31 c3 79 3d a8 e9 d7 c4 6f f5 41 3f 15 21 f7 a8 6c ff cc 71 22 fa 0a c7 53 c0 9a 18 7f 83 bb 4c 45 91 aa 0d 96 45 ab bb a1 15 6d 96 33 9c a3 ea d9 7f 98 20 88 cd 54 a0 55 10 fd d4 10 cc 31 4d 8c 2b 42 76 00 28 39 41 37 37 b7 21 3c 61 d5 50 4f 0d 3d 73 8e 7b fe 67 26 af 1e d7 21 a6 6a e0 9e 9b 57 c5 9a 80 61 ea 98 f8 bb e6 52 c6 ce b2 52 0c 4e dd f0 3e 37 61 7e dd 35 85 9d c4 95 4e 44 4d b4 cf 0e 27 ba 9b 33 d2 db 9f cf 54 4f 58 f2 cd d2 87 7c b5 a2 1e cc ce 35 f1 62 8f f6 3b 66 db 09 7f c2 47 74 70 e1 1f 8c 7d 4c 83 04 24 91 83 f4 1a 15 c7 69 6e e6 b5 ca c2 d7 7b d5}  //weight: 10, accuracy: High
        $x_10_6 = {54 74 90 33 9e 64 7b 6b 06 a6 71 c6 a9 90 81 cd 80 75 e8 7e cf 77 51 33 b8 73 ea 94 0a 1e 6a 81 51 6f 93 43 c9 73 26 d9 1a 3d a4 92 b2 b8 bb 65 3e 02 82 01 a5 40 40 6d 9f a1 c0 45 24 9b 4e c8 9e 15 50 52 63 41 f4 ac 9b 10 85 45 a9 e4 6a 3b 78 73 5c b3 e9 fe 53 0f 96 18 40 02 aa 7a 84 b1 94 08 1d 98 79 67 f1 da d6 d6 be ca c1 9c 0a}  //weight: 10, accuracy: High
        $x_10_7 = {a2 7f a7 8c 62 ab 57 fc 45 46 c5 33 7a d6 82 6e 9e 37 b1 cb bb 8f a0 ea d7 4a fc 31 f7 89 7e 05 de c0 71 99 f5 5d 22 c0 5d 6a c2 08 34 e6 71 ff 6e 33 a4 fa 03 1a c0 f1 97 75 27 26 ce 8b b3 e0 48 3e 76 96 a5 bd a0 54 71 53 e5}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

