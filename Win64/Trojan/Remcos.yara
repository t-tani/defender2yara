rule Trojan_Win64_Remcos_NR_2147901858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Remcos.NR!MTB"
        threat_id = "2147901858"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Failed to execute the .bat file" ascii //weight: 1
        $x_1_2 = "cmd/Cstart/B" ascii //weight: 1
        $x_1_3 = "Failed to download the filesrc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Remcos_RP_2147919949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Remcos.RP!MTB"
        threat_id = "2147919949"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "205"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "Kronus.exe" ascii //weight: 100
        $x_100_2 = "Kronus.dll" ascii //weight: 100
        $x_1_3 = "ctx---- [ hijack ]" ascii //weight: 1
        $x_1_4 = "[ KeepUnwinding ]" ascii //weight: 1
        $x_1_5 = "bcrypt.dll" ascii //weight: 1
        $x_1_6 = "PROCESSOR_COUNT" ascii //weight: 1
        $x_1_7 = "anonymous namespace'" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

