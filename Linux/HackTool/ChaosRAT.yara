rule HackTool_Linux_ChaosRAT_DA_2147979703_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/ChaosRAT.DA!MTB"
        threat_id = "2147979703"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "ChaosRAT"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {65 62 73 6f 63 6b 65 74 09 76 31 2e 35 2e 31 09 68 31 3a 67 6d 7a 74 6e 30 4a 6e 48 56 74 39 4a 5a 71 75 52 75 7a 4c 77 33 67 34 77 6f 75 4e 56 7a 4b 4c 31 35 69 4c 72 2f 7a 6e 2f 51 59 3d 0a 64 65 70 09 67 69 74 68 75 62 2e 63 6f 6d 2f 6a 65 7a 65 6b 2f 78 67 62 09 76 31 2e 31 2e 30 09 68 31 3a 77 6e 70 78 4a 7a 50 31 2b 72 6b 62 47 63 6c 45 6b 6d 77 70 56 46 51 57 70 75 45 32 50 55 47 4e 55 7a 50 38 53 62 66 46 6f 62 6b 3d 0a 64 65 70 09 67 69}  //weight: 10, accuracy: High
        $x_10_2 = {29 73 68 2d 63 25 73 69 29 29 28 7b 7d 22 3a 4d 20 28 22 22 29 29 20 29 0a 20 40 73 20 2d 3e 20 50 6e 3d 5d 5b 7d 0a 5d 0a 3e 20 0a 20 09 20 20 2b 38 30 3b 20 3a 25 20 2c 68 32 5d 3a 25 76 0d 0a 4f 4b 31 33 77 73 7c 30 7c 31 5c 5c 5c 22 25 78 32 35 69 70 3f 3f 35 33 69 76 4c 6c 4c 74 4c 75 4d 6e 43 63 22 0a 20 09 54 6f 41 34 56 31 56 36 56 32 56 33 56 35 41 33 69 64 30 62 30 78 30 58}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

