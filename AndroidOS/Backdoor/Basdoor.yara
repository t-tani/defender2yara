rule Backdoor_AndroidOS_Basdoor_A_2147815436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Basdoor.A!MTB"
        threat_id = "2147815436"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Basdoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/rat.php" ascii //weight: 1
        $x_1_2 = "_sendlargesms" ascii //weight: 1
        $x_1_3 = "~test.test" ascii //weight: 1
        $x_1_4 = "result=ok&action=nwmessage&androidid=" ascii //weight: 1
        $x_1_5 = "SendSingleMessage" ascii //weight: 1
        $x_1_6 = "getdevicefullinfo" ascii //weight: 1
        $x_1_7 = "hideicon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Backdoor_AndroidOS_Basdoor_B_2147815437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Basdoor.B!MTB"
        threat_id = "2147815437"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Basdoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hideAppIcon" ascii //weight: 1
        $x_1_2 = "_sendlargesms" ascii //weight: 1
        $x_1_3 = "I Have Access :)" ascii //weight: 1
        $x_1_4 = "@rootDrDev:" ascii //weight: 1
        $x_1_5 = "getAllSMS" ascii //weight: 1
        $x_1_6 = "getcontacts" ascii //weight: 1
        $x_1_7 = "bomb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Backdoor_AndroidOS_Basdoor_D_2147819179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Basdoor.D!MTB"
        threat_id = "2147819179"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Basdoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/panel.php?link" ascii //weight: 1
        $x_1_2 = "action=hide_all&android_id=" ascii //weight: 1
        $x_1_3 = "action=lastsms&android_id=" ascii //weight: 1
        $x_1_4 = "action=install&android_id=" ascii //weight: 1
        $x_1_5 = "action=upload&android_id=" ascii //weight: 1
        $x_1_6 = "action=clipboard&android_id=" ascii //weight: 1
        $x_1_7 = "action=deviceinfo&android_id=" ascii //weight: 1
        $x_1_8 = "hideAppIcon" ascii //weight: 1
        $x_1_9 = "all-sms.txt" ascii //weight: 1
        $x_1_10 = "Call_Log.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Backdoor_AndroidOS_Basdoor_C_2147840514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Basdoor.C!MTB"
        threat_id = "2147840514"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Basdoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "result=ok&action=nwmessage&androidid=" ascii //weight: 1
        $x_1_2 = "result=ok&action=ping&androidid=" ascii //weight: 1
        $x_1_3 = "~test.test" ascii //weight: 1
        $x_1_4 = "SendSingleMessage" ascii //weight: 1
        $x_1_5 = "hideicon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_AndroidOS_Basdoor_E_2147906017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Basdoor.E!MTB"
        threat_id = "2147906017"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Basdoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "url.php?app=10" ascii //weight: 1
        $x_1_2 = "_getewayurl" ascii //weight: 1
        $x_1_3 = "PhoneSms" ascii //weight: 1
        $x_1_4 = "com.lyufo.play" ascii //weight: 1
        $x_1_5 = "_messagesent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

