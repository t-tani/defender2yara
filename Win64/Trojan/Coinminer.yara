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

