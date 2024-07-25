rule Backdoor_MacOS_GoDoor_A_2147899716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/GoDoor.A!MTB"
        threat_id = "2147899716"
        type = "Backdoor"
        platform = "MacOS: "
        family = "GoDoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.sendFileToMythic" ascii //weight: 1
        $x_1_2 = "GetFileFromMythic" ascii //weight: 1
        $x_1_3 = "main.aggregateDelegateMessagesToMythic" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

