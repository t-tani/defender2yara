rule Trojan_Win64_Coinminer_SA_2147731061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Coinminer.SA"
        threat_id = "2147731061"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Coinminer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\YJ_Project\\Mining_cpp\\Conhost\\x64\\Release\\conhost.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Coinminer_A_2147760675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Coinminer.A!MTB"
        threat_id = "2147760675"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Coinminer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 55 9c 49 bd a8 2a a1 df ad 5d 93 cf 4d 33 ed 4f 8d ?? ?? ?? ?? ?? ?? 66 41 f7 d5 4e 8b ?? ?? ?? ?? ?? ?? 48 c7 44 24 08 ?? ?? ?? ?? ff 74 24 00 9d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Coinminer_A_2147760675_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Coinminer.A!MTB"
        threat_id = "2147760675"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Coinminer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "/Create /F /TN WindowsUpdateBoot /SC ONSTART /RU SYSTEM /RL HIGHEST" ascii //weight: 30
        $x_20_2 = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\WindowsUpdate.vbs" ascii //weight: 20
        $x_10_3 = "runtime_donate_phase.json" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Coinminer_SBR_2147772781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Coinminer.SBR!MSR"
        threat_id = "2147772781"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Coinminer"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "pool.supportxmr.com" wide //weight: 5
        $x_1_2 = "Haku\\obj\\Debug\\msis.pdb" ascii //weight: 1
        $x_1_3 = "DisableAntiSpyware" wide //weight: 1
        $x_1_4 = "Policies\\Microsoft\\Windows Defender" wide //weight: 1
        $x_1_5 = "currency monero" wide //weight: 1
        $x_1_6 = "start the miner process" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Coinminer_RB_2147896802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Coinminer.RB!MTB"
        threat_id = "2147896802"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Coinminer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 89 c2 41 83 e2 1f 45 32 0c 12 44 88 0c 07 48 ff c0 48 39 c6 74 ac}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Coinminer_NCA_2147901139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Coinminer.NCA!MTB"
        threat_id = "2147901139"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Coinminer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {45 33 c0 41 8d 50 ?? 33 c9 48 8b 03 ff 15 61 17 00 00 e8 68 06 00 00 48 8b d8}  //weight: 5, accuracy: Low
        $x_5_2 = {33 d2 48 8d 0d ?? ?? ?? ?? e8 f6 dc ff ff 8b d8 e8 c3 07 00 00 84 c0 74 50}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Coinminer_PAIB_2147975402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Coinminer.PAIB!MTB"
        threat_id = "2147975402"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Coinminer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "cmd.exe /C reagentc /disable" ascii //weight: 3
        $x_3_2 = "cmd.exe /C powercfg /hibernate off" ascii //weight: 3
        $x_1_3 = "/grant Administrators:F" ascii //weight: 1
        $x_1_4 = "/deny Everyone:RX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Coinminer_SJ_2147979751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Coinminer.SJ!MTB"
        threat_id = "2147979751"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Coinminer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "--algorithm pearlhash --pool prl.kryptex.network:7048" wide //weight: 2
        $x_2_2 = {2d 00 2d 00 77 00 61 00 6c 00 6c 00 65 00 74 00 20 00 70 00 72 00 6c 00 31 00 70 00 34 00 7a 00 73 00 70 00 71 00 66 00 77 00 76 00 61 00 76 00 34 00 61 00 7a 00 79 00 78 00 67 00 71 00 33 00 73 00 33 00 67 00 7a 00 66 00 32 00 76 00 73 00 75 00 38 00 7a 00 36 00 74 00 63 00 68 00 38 00 66 00 35 00 72 00 32 00 36 00 38 00 6b 00 61 00 63 00 35 00 37 00 74 00 74 00 34 00 61 00 7a 00 63 00 71 00 36 00 6a 00 66 00 30 00 6a 00 78 00 2e 00 [0-47] 25 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 6e 00 61 00 6d 00 65 00 25 00}  //weight: 2, accuracy: Low
        $x_2_3 = {2d 00 2d 00 77 00 61 00 6c 00 6c 00 65 00 74 00 20 00 70 00 72 00 6c 00 31 00 70 00 70 00 75 00 6d 00 76 00 76 00 77 00 77 00 73 00 6b 00 68 00 71 00 6d 00 73 00 30 00 34 00 71 00 33 00 68 00 33 00 6a 00 6c 00 71 00 64 00 37 00 72 00 70 00 72 00 72 00 32 00 71 00 75 00 38 00 71 00 6b 00 6c 00 6c 00 73 00 36 00 32 00 33 00 68 00 6e 00 33 00 6d 00 6b 00 6d 00 6c 00 72 00 63 00 33 00 38 00 73 00 61 00 67 00 73 00 73 00 77 00 6c 00 2e 00 [0-47] 25 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 6e 00 61 00 6d 00 65 00 25 00}  //weight: 2, accuracy: Low
        $x_2_4 = "guanchor.dll" wide //weight: 2
        $x_1_5 = "freeaddrinfo" ascii //weight: 1
        $x_1_6 = "getaddrinfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

