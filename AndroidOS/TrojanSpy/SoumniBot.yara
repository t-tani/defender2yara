rule TrojanSpy_AndroidOS_SoumniBot_A_2147910827_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SoumniBot.A!MTB"
        threat_id = "2147910827"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SoumniBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "send sms phoneNumber" ascii //weight: 1
        $x_1_2 = "send sms message" ascii //weight: 1
        $x_1_3 = "app@phone1-spy.com" ascii //weight: 1
        $x_1_4 = "/mqtt" ascii //weight: 1
        $x_1_5 = "mainsite" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

