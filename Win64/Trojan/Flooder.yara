rule Trojan_Win64_Flooder_AA_2147977754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Flooder.AA!MTB"
        threat_id = "2147977754"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Flooder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 8b 4c 24 50 48 8b 7c 24 40 48 8b 74 24 58 4c 8b 44 24 48 49 89 c1 49 89 da 48 8b 44 24 70 48 8b 5c 24 78}  //weight: 5, accuracy: High
        $x_6_2 = "main.getCredLeak" ascii //weight: 6
        $x_4_3 = "main.Decode" ascii //weight: 4
        $x_7_4 = "main.getAdminCredLeak.deferwrap1" ascii //weight: 7
        $x_3_5 = "main.findSysCmd" ascii //weight: 3
        $x_8_6 = "main.decideInfectPayload" ascii //weight: 8
        $x_2_7 = "main.exploitDevice" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

