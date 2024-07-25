rule Trojan_Win32_QbotCore_A_2147763222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QbotCore.A!MTB"
        threat_id = "2147763222"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QbotCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dbg_%s_%u_qbotdll.txt" ascii //weight: 1
        $x_1_2 = "qbot_dll_main" ascii //weight: 1
        $x_1_3 = "InitCoreData(): COREFLAG_LOAD_DLL_FROM_MEM wszQbotinjExePath=" ascii //weight: 1
        $x_1_4 = "InitCoreData(): COREFLAG_LOAD_QBOT_HOOK wszQbotinjExePath=" ascii //weight: 1
        $x_1_5 = "InitCoreData(): szSid='%s' wszUserName='%S' wszDomainName='%S' wszQbotinjExe='%S' wszHomeDir='%S' szVarsMutex='%s' szBaseRandomName='%s'" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QbotCore_A_2147763669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QbotCore.A!!Qbot.gen!MTB"
        threat_id = "2147763669"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QbotCore"
        severity = "Critical"
        info = "Qbot: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dbg_%s_%u_qbotdll.txt" ascii //weight: 1
        $x_1_2 = "qbot_dll_main" ascii //weight: 1
        $x_1_3 = "InitCoreData(): COREFLAG_LOAD_DLL_FROM_MEM wszQbotinjExePath=" ascii //weight: 1
        $x_1_4 = "InitCoreData(): COREFLAG_LOAD_QBOT_HOOK wszQbotinjExePath=" ascii //weight: 1
        $x_1_5 = "InitCoreData(): szSid='%s' wszUserName='%S' wszDomainName='%S' wszQbotinjExe='%S' wszHomeDir='%S' szVarsMutex='%s' szBaseRandomName='%s'" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

