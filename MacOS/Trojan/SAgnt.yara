rule Trojan_MacOS_SAgnt_B_2147850535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SAgnt.B!MTB"
        threat_id = "2147850535"
        type = "Trojan"
        platform = "MacOS: "
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2f 67 65 61 63 6f 6e 5f [0-16] 2f 6d 61 69 6e 2e 67 6f}  //weight: 5, accuracy: Low
        $x_5_2 = "cs_gencon/main.go" ascii //weight: 5
        $x_1_3 = "runtime.persistentalloc" ascii //weight: 1
        $x_1_4 = "process).kill" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_MacOS_SAgnt_C_2147888515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SAgnt.C!MTB"
        threat_id = "2147888515"
        type = "Trojan"
        platform = "MacOS: "
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.createPlist" ascii //weight: 1
        $x_1_2 = "MPAgent.go" ascii //weight: 1
        $x_1_3 = "stopad" ascii //weight: 1
        $x_1_4 = "libc_execve_trampoline" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_SAgnt_D_2147927666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SAgnt.D!MTB"
        threat_id = "2147927666"
        type = "Trojan"
        platform = "MacOS: "
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 8a 31 40 84 f6 74 ?? 40 38 f0 75 ?? 48 ff c1 8a 02 48 ff c2 84 c0 75 ?? 31 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {89 d1 80 e1 38 49 89 f0 49 d3 e8 44 30 07 48 83 c2 08 48 ff c7 48 83 fa 50 75 ?? c6 40 0a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

