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

