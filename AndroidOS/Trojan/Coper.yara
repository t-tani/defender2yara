rule Trojan_AndroidOS_Coper_A_2147787714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Coper.A"
        threat_id = "2147787714"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Coper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "injectsFilled" ascii //weight: 4
        $x_4_2 = "intercept_off" ascii //weight: 4
        $x_4_3 = "devadmin_confirm" ascii //weight: 4
        $x_4_4 = "last_keylog_send" ascii //weight: 4
        $x_4_5 = "RES_PARSE_TASKS" ascii //weight: 4
        $x_4_6 = "EXC_INJ_ACT" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Coper_B_2147845867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Coper.B"
        threat_id = "2147845867"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Coper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/downloadinject?access=" ascii //weight: 2
        $x_2_2 = "startHiddenPush" ascii //weight: 2
        $x_2_3 = "specificBatteryOpt" ascii //weight: 2
        $x_2_4 = "&type=html&botid=" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Coper_A_2147894544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Coper.A!MTB"
        threat_id = "2147894544"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Coper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c4 10 6a 27 6a 27 57 8d bc 24 bb 01 00 00 57 e8 65 1a 00 00 83 c4 10 6a 27 6a 27 ff 74 24 40 57 e8 54 1a 00 00 83 c4 10 6a 27 6a 27 56 57 e8 46 1a 00 00 83 c4 10 6a 27 6a 27 56 89 fe 57 e8 36}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Coper_B_2147915008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Coper.B!MTB"
        threat_id = "2147915008"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Coper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EXC_HIDE_INT" ascii //weight: 1
        $x_1_2 = "verifyappssettingsactivity" ascii //weight: 1
        $x_1_3 = "acsb_pages" ascii //weight: 1
        $x_1_4 = "inj_acsb" ascii //weight: 1
        $x_1_5 = "EXC_SMARTS_SHOW" ascii //weight: 1
        $x_1_6 = "injects_to_disable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

