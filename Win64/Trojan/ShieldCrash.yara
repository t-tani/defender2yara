rule Trojan_Win64_ShieldCrash_VA_2147977881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShieldCrash.VA!MTB"
        threat_id = "2147977881"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShieldCrash"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Release\\ShieldCrash.pdb" ascii //weight: 1
        $x_1_2 = "windows defender registry key" ascii //weight: 1
        $x_1_3 = "UNC\\localhost" wide //weight: 1
        $x_1_4 = "\\\\.\\globalroot\\BaseNamedObjects\\Restricted\\WD_SHADOW" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

