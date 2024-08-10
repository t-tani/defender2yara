rule Trojan_Win64_Mekoban_DA_2147918474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mekoban.DA!MTB"
        threat_id = "2147918474"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mekoban"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "C:\\Users\\Musquitao" ascii //weight: 20
        $x_1_2 = "LOAD_EXE\\x64\\Release\\LOAD_EXE.pdb" ascii //weight: 1
        $x_10_3 = "Adobe Download Manager" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

