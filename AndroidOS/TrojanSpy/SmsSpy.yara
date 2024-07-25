rule TrojanSpy_AndroidOS_SmsSpy_G_2147780678_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsSpy.G!MTB"
        threat_id = "2147780678"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/phone2/stop/activity/DeleteActivity" ascii //weight: 1
        $x_1_2 = "Lcom/phone/stop6/service/SmsService" ascii //weight: 1
        $x_1_3 = "content://sms/conversations/" ascii //weight: 1
        $x_1_4 = "has_send_phone_info" ascii //weight: 1
        $x_1_5 = "has_send_contacts" ascii //weight: 1
        $x_1_6 = "has_set_send_email_pwd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsSpy_BH_2147786557_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsSpy.BH!xp"
        threat_id = "2147786557"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "org/red/cute/activity" ascii //weight: 1
        $x_1_2 = "/Android/Sma/Log" ascii //weight: 1
        $x_1_3 = {53 6d 73 55 70 6c 6f 61 64 4d 61 6e 61 67 65 72 20 72 65 73 70 6f 6e 73 65 ef bc 9a}  //weight: 1, accuracy: High
        $x_1_4 = "GetPackageNameService" ascii //weight: 1
        $x_1_5 = "CallLogMonitor" ascii //weight: 1
        $x_1_6 = "SmsMonitor" ascii //weight: 1
        $x_1_7 = {43 6f 6e 74 61 63 74 55 70 6c 6f 61 64 4d 61 6e 61 67 65 72 20 72 65 73 70 6f 6e 73 65 ef bc 9a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsSpy_E_2147793711_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsSpy.E!xp"
        threat_id = "2147793711"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "smspay" ascii //weight: 1
        $x_1_2 = "sms_link_id" ascii //weight: 1
        $x_1_3 = "http://vpay.api.eerichina.com/api/payment" ascii //weight: 1
        $x_1_4 = "com/wyzf/plugin/net" ascii //weight: 1
        $x_1_5 = "Lcom//x90/x02/x15/plugin/model/SmsInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_AndroidOS_SmsSpy_C_2147808868_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsSpy.C"
        threat_id = "2147808868"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DiviceInfo" ascii //weight: 1
        $x_1_2 = "&port=fuckmars" ascii //weight: 1
        $x_1_3 = "/rat.php" ascii //weight: 1
        $x_1_4 = "/upload.php?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsSpy_H_2147815377_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsSpy.H!MTB"
        threat_id = "2147815377"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/api/uploads/postmap" ascii //weight: 1
        $x_1_2 = "getSmsInPhone has executed" ascii //weight: 1
        $x_1_3 = "getAllContacts" ascii //weight: 1
        $x_1_4 = "SMS_URI_ALL" ascii //weight: 1
        $x_1_5 = "uploadGs" ascii //weight: 1
        $x_1_6 = "/api/uploads/photo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsSpy_J_2147817661_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsSpy.J!MTB"
        threat_id = "2147817661"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/phone2/stop/activity/MainActivity" ascii //weight: 1
        $x_1_2 = "content://sms/100" ascii //weight: 1
        $x_1_3 = "has_send_phone_info" ascii //weight: 1
        $x_1_4 = "sendTextMessage" ascii //weight: 1
        $x_1_5 = "has_send_contacts" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsSpy_K_2147829703_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsSpy.K!MTB"
        threat_id = "2147829703"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "smsbomber" ascii //weight: 1
        $x_1_2 = "com/drnull/fcm/smsReceiver" ascii //weight: 1
        $x_1_3 = "hideall" ascii //weight: 1
        $x_1_4 = "POST_NOTOFOCATIONS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsSpy_K_2147829703_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsSpy.K!MTB"
        threat_id = "2147829703"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.aograph.android.agent" ascii //weight: 1
        $x_1_2 = "Fake Arch" ascii //weight: 1
        $x_1_3 = "getContacts" ascii //weight: 1
        $x_1_4 = "getRunning_packages" ascii //weight: 1
        $x_1_5 = "getMessage" ascii //weight: 1
        $x_1_6 = "installNetworkMonitor" ascii //weight: 1
        $x_1_7 = "addLocationListener" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

