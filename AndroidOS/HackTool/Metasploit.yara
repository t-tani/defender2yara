rule HackTool_AndroidOS_Metasploit_A_2147782822_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:AndroidOS/Metasploit.A"
        threat_id = "2147782822"
        type = "HackTool"
        platform = "AndroidOS: Android operating system"
        family = "Metasploit"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/metasploit/Screen1.yail" ascii //weight: 1
        $x_1_2 = "Anonymous/ms.sh" ascii //weight: 1
        $x_1_3 = "/joker.sh" ascii //weight: 1
        $x_1_4 = "/package.apk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule HackTool_AndroidOS_Metasploit_D_2147794289_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:AndroidOS/Metasploit.D!MTB"
        threat_id = "2147794289"
        type = "HackTool"
        platform = "AndroidOS: Android operating system"
        family = "Metasploit"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/metasploit.dat" ascii //weight: 1
        $x_1_2 = "metasploit/PayloadTrustManager.class" ascii //weight: 1
        $x_1_3 = "Lcom/metasploit/meterpreter/AndroidMeterpreter" ascii //weight: 1
        $x_1_4 = "Lmetasploit/JMXPayload" ascii //weight: 1
        $x_1_5 = "AndroidMeterpreter" ascii //weight: 1
        $x_1_6 = "android_dump_calllog" ascii //weight: 1
        $x_1_7 = "android_dump_contacts" ascii //weight: 1
        $x_1_8 = "clipboard_monitor_dump" ascii //weight: 1
        $x_1_9 = "stdapi_webcam_audio_record_android" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

