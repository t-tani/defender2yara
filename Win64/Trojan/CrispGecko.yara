rule Trojan_Win64_CrispGecko_A_2147979844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CrispGecko.A"
        threat_id = "2147979844"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CrispGecko"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3d 3d 3d 20 57 6f 72 6b 65 72 20 28 53 74 61 74 69 63 29 20 3d 3d 3d 0a 0a 00}  //weight: 1, accuracy: High
        $x_1_2 = {3d 3d 3d 20 47 31 31 20 4b 69 6c 6c 65 72 20 73 74 61 72 74 65 64 20 76 69 61 20 49 6e 69 74 69 61 6c 69 7a 65 20 3d 3d 3d 0a 0a 00}  //weight: 1, accuracy: High
        $x_1_3 = {5b 2a 5d 20 43 6c 65 61 6e 69 6e 67 20 75 70 20 70 72 65 76 69 6f 75 73 20 64 72 69 76 65 72 2e 2e 2e 0a 00}  //weight: 1, accuracy: High
        $x_1_4 = {5b 2b 5d 20 53 70 61 77 6e 65 64 20 72 75 6e 64 6c 6c 33 32 20 6b 69 6c 6c 65 72 20 70 72 6f 63 65 73 73 0a 00}  //weight: 1, accuracy: High
        $x_1_5 = {5b 2b 5d 20 53 74 61 72 74 69 6e 67 20 6d 6f 6e 69 74 6f 72 69 6e 67 20 6c 6f 6f 70 2e 2e 2e 0a 0a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

