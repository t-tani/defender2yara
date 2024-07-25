rule Trojan_Win64_Nekark_EC_2147850518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Nekark.EC!MTB"
        threat_id = "2147850518"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Nekark"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {40 32 2c 02 41 88 2c 3c 48 83 c7 01 49 39 fd 0f 84 0e 01 00 00}  //weight: 4, accuracy: High
        $x_1_2 = "bjzcknpjq|zbznwhwdgaolyqxzkhpwdlbjjc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

