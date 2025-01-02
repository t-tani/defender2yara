rule VirTool_Win64_MalTelHelper_A_2147929507_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/MalTelHelper.A"
        threat_id = "2147929507"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "MalTelHelper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{\"idx\":%i,\"addr\":%llu,\"page_addr\":%llu,\"size\":%zu,\"state\":%lu,\"protect\":\"%s\",\"type\":\"%s\"}" wide //weight: 1
        $x_1_2 = "{\"type\":\"dll\",\"func\":" wide //weight: 1
        $x_1_3 = "\"pid\":%lu,\"tid\":%lu}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

