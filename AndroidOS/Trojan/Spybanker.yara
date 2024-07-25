rule Trojan_AndroidOS_Spybanker_P_2147850577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Spybanker.P"
        threat_id = "2147850577"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Spybanker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Sms2ReceiverForManifest" ascii //weight: 2
        $x_2_2 = "BackgroundServiceStarterReceiver" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

