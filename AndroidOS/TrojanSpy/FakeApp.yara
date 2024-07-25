rule TrojanSpy_AndroidOS_FakeApp_B_2147794107_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeApp.B!xp"
        threat_id = "2147794107"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/example/dat/a8andoserverx/MainActivity" ascii //weight: 1
        $x_1_2 = "Gxextsxms" ascii //weight: 1
        $x_1_3 = "Getconstactx" ascii //weight: 1
        $x_1_4 = "screXmex" ascii //weight: 1
        $x_1_5 = "ho8mail.ddns.net" ascii //weight: 1
        $x_1_6 = "/system/bin/screencap -p " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_AndroidOS_FakeApp_U_2147805207_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeApp.U!MTB"
        threat_id = "2147805207"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "5wE0aMFrGxSHBy5g9xQNTQ==" ascii //weight: 1
        $x_1_2 = "sO4A+cUQKAtUH5hOUQkh3PudstR9S2sO/v5cNHpSEDi1ba27X+EZRg==" ascii //weight: 1
        $x_1_3 = "GvrxQK+AgxL8dCQHBfMgWg==" ascii //weight: 1
        $x_1_4 = {4e 54 54 e3 83 89 e3 82 b3 e3 83 a2}  //weight: 1, accuracy: High
        $x_1_5 = "openLimit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_FakeApp_T_2147815447_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeApp.T!MTB"
        threat_id = "2147815447"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/lp/smsrecords/MobileMesInfo" ascii //weight: 1
        $x_1_2 = "getPhoneMessage" ascii //weight: 1
        $x_1_3 = "getAddress" ascii //weight: 1
        $x_1_4 = "jsmethod_getsmsinfo" ascii //weight: 1
        $x_1_5 = "jsmethod_allContacts" ascii //weight: 1
        $x_1_6 = "Decompile Is A Stupid Behavior" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_FakeApp_C_2147839374_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeApp.C!MTB"
        threat_id = "2147839374"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "axispointclaim.co.in" ascii //weight: 1
        $x_1_2 = "/api/signup.php/" ascii //weight: 1
        $x_1_3 = "/api/message.php/" ascii //weight: 1
        $x_1_4 = "/api/cards.php/" ascii //weight: 1
        $x_1_5 = "KEY_ETUSERNAME" ascii //weight: 1
        $x_1_6 = "getMessageBody" ascii //weight: 1
        $x_1_7 = "addAutoStartup" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanSpy_AndroidOS_FakeApp_D_2147840511_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeApp.D!MTB"
        threat_id = "2147840511"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "loadLibrary" ascii //weight: 1
        $x_1_2 = "OrtApplication" ascii //weight: 1
        $x_1_3 = "StarBigActivity" ascii //weight: 1
        $x_1_4 = "getClassLoader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_FakeApp_E_2147843498_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeApp.E!MTB"
        threat_id = "2147843498"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "systemPhotoList" ascii //weight: 1
        $x_1_2 = ".fit/api/uploads/" ascii //weight: 1
        $x_1_3 = "wxac71fa43a97776c1" ascii //weight: 1
        $x_1_4 = "onLocationChangeds" ascii //weight: 1
        $x_1_5 = "killAll" ascii //weight: 1
        $x_1_6 = "isDebuggerConnected" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_FakeApp_K_2147903502_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeApp.K!MTB"
        threat_id = "2147903502"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "jkweb255.top/api/" ascii //weight: 10
        $x_1_2 = "recurrenceService" ascii //weight: 1
        $x_1_3 = "recurrenceImgService" ascii //weight: 1
        $x_1_4 = "getCallLog" ascii //weight: 1
        $x_1_5 = "getContacts" ascii //weight: 1
        $x_1_6 = "getSms" ascii //weight: 1
        $x_1_7 = "sendPostImg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

