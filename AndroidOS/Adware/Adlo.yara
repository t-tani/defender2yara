rule Adware_AndroidOS_Adlo_A_348570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Adlo.A!MTB"
        threat_id = "348570"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Adlo"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {1c 00 00 00 6e 10 ?? 01 01 00 0a 00 23 00 ?? 00 6e 20 ?? 01 01 00 6e 10 ?? 01 01 00 71 10 ?? 01 00 00 0c 01 6e 20 ?? 01 12 00 6e 10 ?? 01 02 00}  //weight: 10, accuracy: Low
        $x_10_2 = {12 00 00 00 21 ?? 23 00 ?? 00 12 01 [0-5] 35 [0-3] 00 48 [0-8] 8d ?? 4f ?? 00 ?? d8 [0-3] 01}  //weight: 10, accuracy: Low
        $x_1_3 = "createNewFile" ascii //weight: 1
        $x_1_4 = "BaseDexClassLoader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

