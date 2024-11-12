rule Trojan_Win64_Midie_SIB_2147807755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Midie.SIB!MTB"
        threat_id = "2147807755"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "XVI32_Load" ascii //weight: 10
        $x_10_2 = "DllInstall" ascii //weight: 10
        $x_10_3 = "XVI32_Close" ascii //weight: 10
        $x_10_4 = "XVI32_init" ascii //weight: 10
        $x_1_5 = {4c 3b 7c 24 60 7d ?? 4c 8b 7c 24 50 48 8b 6c 24 58 55 48 8b 44 24 ?? 5d 48 01 c5 48 0f be 45 00 49 31 c7 49 81 e7 ff 00 00 00 48 8b 2d 9b 84 05 00 49 c1 e7 ?? 4d 8b 3c 2f 4c 8b 74 24 50 49 c1 fe ?? 49 81 e6 ff ff ff 00 4d 31 f7 4c 89 7c 24 50 4c 8b 7c 24 ?? 49 ff c7 4c 89 7c 24 04 eb}  //weight: 1, accuracy: Low
        $x_1_6 = {48 c7 c0 08 00 00 00 48 3b 44 24 ?? 7c ?? 4c 8b 7c 24 ?? 49 83 e7 01 4d 21 ff 74 ?? 4c 63 7c 24 ?? 4c 8b 74 24 02 49 d1 ?? 49 81 e6 ff ff ff 7f 4d 31 f7 4c 89 7c 24 02 eb ?? 4c 8b 7c 24 02 49 d1 ?? 49 81 e7 ff ff ff 7f 4c 89 7c 24 02 48 ff 44 24 00 71 ?? ff 74 24 02 4c 8b 7c 24 ?? 48 8b 2d ?? ?? ?? ?? 49 c1 e7 ?? 58 49 89 04 2f 48 ff 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Midie_NM_2147904896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Midie.NM!MTB"
        threat_id = "2147904896"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "RWSafe.pdb" ascii //weight: 2
        $x_2_2 = "GPT 1.6" ascii //weight: 2
        $x_1_3 = "Baat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Midie_NM_2147904896_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Midie.NM!MTB"
        threat_id = "2147904896"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {40 b7 01 40 88 7c 24 20 8a cb e8 bc fd ff ff e8 9b 0b 00 00 48 8b d8 48 83 38 00}  //weight: 3, accuracy: High
        $x_2_2 = {48 8b c8 e8 0a fd ff ff 84 c0 74 16 48 8b 1b 48 8b cb e8 b7 00 00 00 45 33 c0 41 8d 50 02 33 c9 ff d3 e8 73 0b 00 00 48 8b d8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Midie_GXZ_2147908904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Midie.GXZ!MTB"
        threat_id = "2147908904"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f b6 02 41 88 00 88 0a 0f b6 54 24 31 44 0f b6 44 24 30 0f b6 4c 14 32 42 02 4c 04 32 0f b6 c1 0f b6 4c 04 32 42 32 4c 17 f7 41 88 4a ff 49 83 eb 01}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Midie_GP_2147914443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Midie.GP!MTB"
        threat_id = "2147914443"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dbdjUKLXxZzyf" ascii //weight: 1
        $x_1_2 = "KYgWGvLdWnJMcT" ascii //weight: 1
        $x_1_3 = "xrEAfFrCHbBCE0" ascii //weight: 1
        $x_1_4 = "EaVMlTKHmPPIYKX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Midie_ASJ_2147922485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Midie.ASJ!MTB"
        threat_id = "2147922485"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {48 8b d0 4c 8d 05 ?? ?? ff ff 49 8b cf 48 8b f8 ff 15 ?? ?? ?? ?? 4c 89 6c 24 30 4c 8b cf 44 89 6c 24 28 45 33 c0 33 d2 48 89 5c 24 20 49 8b cf ff 15 ?? ?? ?? ?? 41 b9 18 00 00 00 4c 89 6c 24 20 4c 8d 44 24 50 48 8b d3 49 8b cf ff 15 ?? ?? ?? ?? b9 64 00 00 00 ff 15}  //weight: 4, accuracy: Low
        $x_1_2 = {49 8d 04 30 49 2b d0 0f 1f 40 00 0f 1f 84 00 00 00 00 00 44 30 38 48 8d 40 01 48 83 ea 01 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

