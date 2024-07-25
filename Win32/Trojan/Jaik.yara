rule Trojan_Win32_Jaik_GIC_2147845971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jaik.GIC!MTB"
        threat_id = "2147845971"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c6 45 bc 49 c6 45 bd 6e c6 45 be 74 c6 45 bf 65 c6 45 c0 72 c6 45 c1 6e c6 45 c2 65 c6 45 c3 74 c6 45 c4 52 c6 45 c5 65 c6 45 c6 61 c6 45 c7 64 c6 45 c8 46 c6 45 c9 69 c6 45 ca 6c c6 45 cb 65}  //weight: 10, accuracy: High
        $x_1_2 = "cmd /c start C:\\ProgramData\\114514" ascii //weight: 1
        $x_1_3 = "cmd /c taskkill /f /t /im mmc.exe" ascii //weight: 1
        $x_1_4 = "C:\\ProgramData\\114514" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Jaik_GPC_2147891513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jaik.GPC!MTB"
        threat_id = "2147891513"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8b d7 2b d6 0f af 55 10 03 d3 0f af d3 6b d2 b2 01 95 d0 fc ff ff 8a c3 32 85 cb fc ff ff 66 83 3d 68 31 42 00 00 75 13}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Jaik_GMX_2147893482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jaik.GMX!MTB"
        threat_id = "2147893482"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 7a 5b 6b f4 f5 18 6d 66}  //weight: 10, accuracy: High
        $x_10_2 = {08 5d 2c 7d ?? 0b 96 ?? ?? ?? ?? 53 14 e7 32 6b 77 b9 ?? ?? ?? ?? 2d}  //weight: 10, accuracy: Low
        $x_1_3 = "b05jnlygj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Jaik_GNS_2147894653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jaik.GNS!MTB"
        threat_id = "2147894653"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {34 d8 13 0d ?? ?? ?? ?? 31 2b 79 31 f3 5a 8a c4 d0 c3}  //weight: 10, accuracy: Low
        $x_1_2 = "b4vNiR7Ca" ascii //weight: 1
        $x_1_3 = "P.vmp0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Jaik_GZA_2147901353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jaik.GZA!MTB"
        threat_id = "2147901353"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 4c 24 14 03 4c 24 04 8b 6c 24 1c 03 2c 24 8a 11 8a 7d 00 30 fa 88 11 83 44 24 04 02 ff 04 24 8b 1c 24 8b 7c 24 20 4f 39 fb}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Jaik_HNA_2147909117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jaik.HNA!MTB"
        threat_id = "2147909117"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 65 52 65 73 74 6f 72 65 50 72 69 76 69 6c 65 67 65 00 00 25 64 00 00 2e 74 6f 70 3a}  //weight: 1, accuracy: High
        $x_1_2 = {73 74 72 52 65 6d 6f 76 65 53 70 65 63 43 68 61 72 20 70 61 72 61 6d 20 65 72 72 6f 72 0a 00 00 32 31 34 37 34 38 33 36 35 30 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

