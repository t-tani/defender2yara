rule Trojan_Win64_KillAV_A_2147851753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KillAV.A!MTB"
        threat_id = "2147851753"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KillAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\.\\PROCEXP152" ascii //weight: 2
        $x_2_2 = "Except in KillProcessHandles" ascii //weight: 2
        $x_2_3 = "DeviceIoControl to Driver" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_KillAV_B_2147851898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KillAV.B!MTB"
        threat_id = "2147851898"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KillAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Extracting the driver to %ws" wide //weight: 2
        $x_2_2 = "Could not load driver %s may be loaded" wide //weight: 2
        $x_2_3 = "NoConnectTo %s Device" wide //weight: 2
        $x_2_4 = "PROCEXP.SYS" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_KillAV_RPX_2147895318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KillAV.RPX!MTB"
        threat_id = "2147895318"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KillAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 4c 24 08 56 57 48 81 ec 88 00 00 00 c6 44 24 68 00 48 8d 44 24 69 48 8b f8 33 c0 b9 09 00 00 00 f3 aa 48 8d 44 24 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_KillAV_RPY_2147895319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KillAV.RPY!MTB"
        threat_id = "2147895319"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KillAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 c9 10 2b c1 35 74 23 30 02 8b c8 48 c1 e1 08 48 c1 e8 18 48 0b c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_KillAV_MKX_2147897033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KillAV.MKX!MTB"
        threat_id = "2147897033"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KillAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 0f 44 dc 4c 89 f0 31 d2 49 f7 f2 49 89 d0 48 89 d9 48 d1 e9 49 0f af ca 48 89 d8 31 d2 48 f7 f1 48 d1 e8 48 0f af d8 48 89 da c4 c2 fb f6 c5 43 8a 0c 31 43 32 0c 03 48 c1 e8 ?? 30 c1 43 88 0c 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_KillAV_DA_2147917260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KillAV.DA!MTB"
        threat_id = "2147917260"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KillAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "56"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "AV_KILLER" ascii //weight: 50
        $x_1_2 = "sc.exe create" ascii //weight: 1
        $x_1_3 = "sc.exe start " ascii //weight: 1
        $x_1_4 = ".\\TrueSight" ascii //weight: 1
        $x_1_5 = "MsMpEng.exe" ascii //weight: 1
        $x_1_6 = "Driver file created" ascii //weight: 1
        $x_1_7 = "Successfully terminated process" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_KillAV_BSA_2147928706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KillAV.BSA!MTB"
        threat_id = "2147928706"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KillAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "RealBlindingEDR" ascii //weight: 20
        $x_5_2 = "Permanently delete AV/EDR" ascii //weight: 5
        $x_5_3 = "driver_path" ascii //weight: 5
        $x_5_4 = "RealBlindingEDR.exe" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*))) or
            (all of ($x*))
        )
}

