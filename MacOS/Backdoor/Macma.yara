rule Backdoor_MacOS_Macma_A_2147798722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Macma.A!MTB"
        threat_id = "2147798722"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Macma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 63 ca 48 89 8d ?? ?? ff ff 48 8b 85 ?? ?? ff ff 48 8b 8d ?? ?? ff ff ba 01 00 00 00 48 8b bd ?? ?? ff ff 48 89 c6 e8 ?? ?? ?? 00 48 89 85 ?? ?? ff ff e9 00 00 00 00 48 8d 85 ?? ?? ff ff 48 89 85 ?? ?? ff ff 48 8d 05 ?? ?? 04 00 48 89 85 ?? ?? ff ff 48 8b bd ?? ?? ff ff 48 89 c6 e8 ?? ?? ?? 00 48 89 85 ?? ?? ff ff e9 00 00 00 00}  //weight: 2, accuracy: Low
        $x_1_2 = "/Library/LaunchAgents/com.UserAgent.va.plist" ascii //weight: 1
        $x_1_3 = "Mutex::~Mutex() pthread_mutex_destroy error,code=%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MacOS_Macma_A_2147799120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Macma.A"
        threat_id = "2147799120"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Macma"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2f 4c 69 62 72 61 72 79 2f 4c 61 75 6e 63 68 41 67 65 6e 74 73 2f 63 6f 6d 2e 55 73 65 72 41 67 65 6e 74 2e [0-16] 2e 70 6c 69 73 74}  //weight: 2, accuracy: Low
        $x_2_2 = "send CDDSMacSearchFile taskid %d ,m_SrcHost %d,m_SrcClient %d ret %d vec %d" ascii //weight: 2
        $x_2_3 = "CDDSRequestDownload:m_nTaskID:%d,m_strRemoteFile:%s,m_strLocalSaveAs:%s" ascii //weight: 2
        $x_1_4 = {28 24 31 3d 3d 22 00 22 29 20 73 79 73 74 65 6d 28 22 6b 69 6c 6c 20 2d 39 20 22 24 32 29 3b 7d 27 00 2e 6b 69 6c 6c 63 68 65 63 6b 65 72 5f 00 22 29}  //weight: 1, accuracy: High
        $x_1_5 = "CDDSScreenCaptureParameterRequest" ascii //weight: 1
        $x_1_6 = "CDDSMacFileListReply" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

