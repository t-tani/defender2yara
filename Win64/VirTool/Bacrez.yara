rule VirTool_Win64_Bacrez_A_2147846428_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Bacrez.A!MTB"
        threat_id = "2147846428"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Bacrez"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RpcStringFree" ascii //weight: 1
        $x_1_2 = "RpcBindingFree" ascii //weight: 1
        $x_1_3 = "namedpipe" ascii //weight: 1
        $x_1_4 = "pipename" ascii //weight: 1
        $x_1_5 = "hostname" ascii //weight: 1
        $x_1_6 = "executewithtoken" ascii //weight: 1
        $x_1_7 = "shutdown" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

