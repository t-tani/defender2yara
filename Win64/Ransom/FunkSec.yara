rule Ransom_Win64_FunkSec_CCJT_2147929816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FunkSec.CCJT!MTB"
        threat_id = "2147929816"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FunkSec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "funksecschtasks /create /tn  /tr \"\" /sc onstart" ascii //weight: 2
        $x_1_2 = "Scheduled task created to run ransomware at startup." ascii //weight: 1
        $x_1_3 = "Set-MpPreference -DisableRealtimeMonitoring" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

