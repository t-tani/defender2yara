rule Trojan_Win64_MoonWalk_A_2147916188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MoonWalk.A!MTB"
        threat_id = "2147916188"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MoonWalk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b6 47 15 33 d9 c1 e3 08 42 0f b6 0c 30 33 d9 41 33 1f 33 1d 4c 37 02 00 44 8b c3 41 89 5f 18 45 33 47 04 45 8b c8 45 89 47 1c 45 33 4f 08 45 8b d1 45 89 4f 20 45 33 57 0c 45 8b da 45 89 57 24 45 33 5f 10 41 8b c3 45 89 5f 28 41 33 47 14 8b d0 48 c1 e8 18 41 89 57 2c 42 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_MoonWalk_NM_2147977717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MoonWalk.NM!MTB"
        threat_id = "2147977717"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MoonWalk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nt.MpTriggerStatusRefreshNotification" ascii //weight: 1
        $x_1_2 = "nt.MpUpdateBrowserActiveTab" ascii //weight: 1
        $x_1_3 = "nt.MpTriggerHeartbeatOnUninstall" ascii //weight: 1
        $x_1_4 = "nt.MpReportClipboardOwner" ascii //weight: 1
        $x_1_5 = "nt.MpDefenderIsPrintAccessCheckNeeded" ascii //weight: 1
        $x_2_6 = "nt.MpCheckAccessForClipboardOperationEx" ascii //weight: 2
        $x_1_7 = "ChangeCipherSpecPayloadAlertMessagePayload" ascii //weight: 1
        $x_1_8 = "Fc/uc/o" ascii //weight: 1
        $x_1_9 = "DJMRMDMCWCPPVSSSDMVHVWZCD" ascii //weight: 1
        $x_1_10 = "PHmolmilmblxloglnktKMKKinHPhaGydBCo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

