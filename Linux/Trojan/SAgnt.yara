rule Trojan_Linux_SAgnt_A_2147825987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SAgnt.A!xp"
        threat_id = "2147825987"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 e5 48 81 ec c0 00 00 00 48 89 bd 48 ff ff ff 48 89 b5 40 ff ff ff c7 45 fc 01 00 00 00 c7 45 f8 00 00 00 00 48 8d 95 50 ff ff ff 48 8b 85 48 ff ff ff 48 89 d6 48 89 c7}  //weight: 1, accuracy: High
        $x_1_2 = {2e 30 00 77 72 69 74 65 00 72 65 61 64 00 5f 5f 65 72 72 6e 6f 5f 6c 6f 63 61 74 69 6f 6e 00 66 6f 72 6b 00 6c}  //weight: 1, accuracy: High
        $x_1_3 = {48 89 e5 48 83 ec 20 89 7d ec 48 89 75 e0 89 55 e8 c7 45 fc 00 00 00 00 c7 45 fc 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Linux_SAgnt_B_2147828996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SAgnt.B!xp"
        threat_id = "2147828996"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sysCmdClientInit" ascii //weight: 1
        $x_1_2 = "sendSysCmdReq" ascii //weight: 1
        $x_1_3 = "CreateNtpPacket" ascii //weight: 1
        $x_1_4 = "netPortDetect.c" ascii //weight: 1
        $x_1_5 = "create_detect_daemon" ascii //weight: 1
        $x_1_6 = "Request cmd is udp" ascii //weight: 1
        $x_1_7 = "begain Filtering" ascii //weight: 1
        $x_1_8 = "begain SendingData" ascii //weight: 1
        $x_1_9 = "Request cmd is connect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Linux_SAgnt_D_2147828997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SAgnt.D!xp"
        threat_id = "2147828997"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 83 ec 20 89 7d ec 48 ?? ?? e0 be 01 00 00 00 bf 11 00 00 00 e8 89 fd ff ff bf a7 0c 40 00 e8 ?? ?? ff ff 48 8b 45 e0 48 8b 00 48 89 c7 e8 ?? ?? ff ff 48 89 c2 b9 a9 0c 40 00 48 8b 45 e0 48 8b 00 48 89 ce 48 89 c7}  //weight: 1, accuracy: Low
        $x_1_2 = {48 c1 e0 03 48 03 45 e0 48 8b 00 48 89 c7 e8 ?? ?? ff ff 48 89 c2 8b 45 fc 48 98 48 c1 e0 03 48 03 45 e0 48 8b 00 be 20 00 00 00 48 89 c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_SAgnt_B_2147831481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SAgnt.B!MTB"
        threat_id = "2147831481"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BotsConnected" ascii //weight: 1
        $x_1_2 = "BOTKILL" ascii //weight: 1
        $x_1_3 = "KILLATTK" ascii //weight: 1
        $x_1_4 = "BotListener" ascii //weight: 1
        $x_1_5 = "BotWorker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Linux_SAgnt_C_2147846768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SAgnt.C!MTB"
        threat_id = "2147846768"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "main.WriteReadme" ascii //weight: 2
        $x_2_2 = "main.ChangePassword" ascii //weight: 2
        $x_1_3 = "/root/bot/main.go" ascii //weight: 1
        $x_1_4 = "patchbot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Linux_SAgnt_E_2147849912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SAgnt.E!MTB"
        threat_id = "2147849912"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 e5 bf 00 00 00 00 b8 00 00 00 00 e8 e0 fe ff ff bf 00 00 00 00 b8 00 00 00 00 e8 c1 fe ff ff ba 00 00 00 00 be 90 06 40 00 bf 95 06 40 00 b8 00 00 00 00 e8 c8 fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_SAgnt_D_2147850527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SAgnt.D!MTB"
        threat_id = "2147850527"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 24 00 18 03 00 74 13 10 1d 16 89 47 c1 57 23 a5 ea 63 bc 5d a3 8b 89 f8 fd 2a 56 96 16 a1 0f 69 51 47 2a 01 37 ec 10 6d b8 e3 e4 10 9f 3e 27 be 82 81 94 d9 e7 33 a5 65 6d 7a b8 7f 6a 5a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_SAgnt_F_2147891310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SAgnt.F!MTB"
        threat_id = "2147891310"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d 35 cc 07 00 00 48 8d 3d c7 07 00 00 ba 01 00 00 00 e8 59 f7 ff ff 48 8b 44 24 48 48 8d bc 24 30 02 00 00 31 d2 48 8b 30 31 c0 e8 a0 f5 ff ff 89 c7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_SAgnt_G_2147891313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SAgnt.G!MTB"
        threat_id = "2147891313"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 84 24 a8 08 00 00 48 83 c0 01 0f b6 00 3c 45 0f 85 b8 00 00 00 48 8b 84 24 a8 08 00 00 48 83 c0 02 0f b6 00 3c 4c 0f 85 a1 00 00 00 48 8b 84 24 a8 08 00 00 48 83 c0 03 0f b6 00 3c 46}  //weight: 1, accuracy: High
        $x_1_2 = {4c 8b 4c 24 10 48 8b 3d e0 1f 1d 00 31 c0 4c 8d 05 f8 cc 15 00 48 8d 0d ab cd 15 00 48 8d 15 06 cd 15 00 be 01 00 00 00 e8 f7 3e ff ff 48 8b 7c 24 10 48 39 df}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Linux_SAgnt_H_2147893752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SAgnt.H!MTB"
        threat_id = "2147893752"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {71 0c 0e 1b 94 a1 c1 a7 85 fb e8 48 60 88 de 98 58 8c 1b b4 5d 97 bc 3e f4 71 44 77 bf 67 92 53 56 a9 6d 60 13 c7 0d d4 1a 12 b0 60 a7 f8 cb ba}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

