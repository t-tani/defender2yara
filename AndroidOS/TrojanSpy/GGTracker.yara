rule TrojanSpy_AndroidOS_GGTracker_AR_2147979459_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/GGTracker.AR!MTB"
        threat_id = "2147979459"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "GGTracker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {67 00 67 00 74 00 72 00 61 00 63 00 6b 00 2e 00 6f 00 72 00 67 00 2f 00 53 00 4d 00 31 00 ?? 3f 00 64 00 65 00 76 00 69 00 63 00 65 00 5f 00 69 00 64 00 3d 00}  //weight: 10, accuracy: Low
        $x_10_2 = {67 67 74 72 61 63 6b 2e 6f 72 67 2f 53 4d 31 ?? 3f 64 65 76 69 63 65 5f 69 64 3d}  //weight: 10, accuracy: Low
        $x_7_3 = "Auto turn on Wi-Fi to update push data" ascii //weight: 7
        $x_4_4 = "Auto turn on Wi-Fi on power connect" ascii //weight: 4
        $x_3_5 = "Notification on low battery" ascii //weight: 3
        $x_6_6 = "Checking data traffic" ascii //weight: 6
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((2 of ($x_10_*) and 1 of ($x_6_*) and 1 of ($x_4_*))) or
            ((2 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_3_*))) or
            ((2 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_4_*))) or
            ((2 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_6_*))) or
            (all of ($x*))
        )
}

