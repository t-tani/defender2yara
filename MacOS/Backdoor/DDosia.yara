rule Backdoor_MacOS_DDosia_K_2147906332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/DDosia.K!MTB"
        threat_id = "2147906332"
        type = "Backdoor"
        platform = "MacOS: "
        family = "DDosia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dtracesemacquiredebug" ascii //weight: 1
        $x_1_2 = "heap dumpasyncpreemptoffforce" ascii //weight: 1
        $x_1_3 = "Pointermime/multipartwrite " ascii //weight: 1
        $x_1_4 = "HanLaoMroNkoVaiudpTCPUDP" ascii //weight: 1
        $x_1_5 = "callGOMEMLIMITBad varintatomic" ascii //weight: 1
        $x_1_6 = "0atomicor8tracebackrwxrwxrwxcomplex64math" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

