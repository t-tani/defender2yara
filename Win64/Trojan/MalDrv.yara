rule Trojan_Win64_MalDrv_B_2147923640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MalDrv.B!MTB"
        threat_id = "2147923640"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MalDrv"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SendTo" ascii //weight: 1
        $x_1_2 = "ReceiveFrom" ascii //weight: 1
        $x_1_3 = "Accept" ascii //weight: 1
        $x_1_4 = "103.117.121.160" ascii //weight: 1
        $x_1_5 = "Hello DriverUnLoad" ascii //weight: 1
        $x_1_6 = "Hello DriverEntry" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_MalDrv_C_2147923641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MalDrv.C!MTB"
        threat_id = "2147923641"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MalDrv"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "103.117.121.160" ascii //weight: 1
        $x_1_2 = "Hello DriverUnLoad" ascii //weight: 1
        $x_1_3 = "Hello DriverEntry" ascii //weight: 1
        $x_1_4 = "\\??\\C:\\CardKey.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_MalDrv_D_2147923642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MalDrv.D!MTB"
        threat_id = "2147923642"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MalDrv"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WhatAmIDoingHere" ascii //weight: 1
        $x_1_2 = "\\DosDevices\\IllusionizeIsGoodAsFuck" ascii //weight: 1
        $x_1_3 = "bateryLifeAll4" ascii //weight: 1
        $x_1_4 = "\\DosDevices\\yesSilentView" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

