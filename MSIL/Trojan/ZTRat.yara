rule Trojan_MSIL_ZTRat_AZR_2147917927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZTRat.AZR!MTB"
        threat_id = "2147917927"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZTRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ZT_RAT" wide //weight: 2
        $x_1_2 = "netsh firewall delete allowedprogram" wide //weight: 1
        $x_1_3 = "/create /f /RL HIGHEST /sc minute /mo 1 /tn" wide //weight: 1
        $x_2_4 = "ZT_RAT_Client.Resources" wide //weight: 2
        $x_1_5 = "/start-recording" wide //weight: 1
        $x_1_6 = "/stop-recording" wide //weight: 1
        $x_1_7 = "/get-microphone" wide //weight: 1
        $x_1_8 = "/sended-camera-capture" wide //weight: 1
        $x_1_9 = "/get-remote-camera" wide //weight: 1
        $x_1_10 = "/run-powershell" wide //weight: 1
        $x_1_11 = "/get-remote-shell" wide //weight: 1
        $x_1_12 = "/kill-process" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

