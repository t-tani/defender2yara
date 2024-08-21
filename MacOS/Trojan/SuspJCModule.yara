rule Trojan_MacOS_SuspJCModule_AP_2147919177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspJCModule.AP"
        threat_id = "2147919177"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspJCModule"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com.docker.sock" ascii //weight: 2
        $x_2_2 = "XorLogger" ascii //weight: 2
        $x_2_3 = "C2CommsLoop" ascii //weight: 2
        $x_1_4 = "DownloadFile" ascii //weight: 1
        $x_1_5 = "UploadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MacOS_SuspJCModule_AX_2147919178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspJCModule.AX"
        threat_id = "2147919178"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspJCModule"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "JC_BUNDLE_ID" ascii //weight: 2
        $x_2_2 = "ranrok" ascii //weight: 2
        $x_2_3 = "JC_WORKFLOW_MSG" ascii //weight: 2
        $x_1_4 = "/Library/Keychains/System.keychain" ascii //weight: 1
        $x_1_5 = "/Library/Keychains/login.keychain-db" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

