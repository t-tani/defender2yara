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

