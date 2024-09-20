rule HackTool_MacOS_Chisel_A_2147839848_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Chisel.A!MTB"
        threat_id = "2147839848"
        type = "HackTool"
        platform = "MacOS: "
        family = "Chisel"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/jpillora/chisel/" ascii //weight: 1
        $x_1_2 = "chiselclientclosedconfigcookie" ascii //weight: 1
        $x_1_3 = "main.generatePidFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MacOS_Chisel_B_2147893467_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Chisel.B!MTB"
        threat_id = "2147893467"
        type = "HackTool"
        platform = "MacOS: "
        family = "Chisel"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CHISEL_CONNECT" ascii //weight: 1
        $x_1_2 = "sendchisel" ascii //weight: 1
        $x_1_3 = "chisel.pid" ascii //weight: 1
        $x_1_4 = "chiselclientclosed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MacOS_Chisel_C_2147921463_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Chisel.C!MTB"
        threat_id = "2147921463"
        type = "HackTool"
        platform = "MacOS: "
        family = "Chisel"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/jpillora/chisel/share/ccrypto.IsChiselKey" ascii //weight: 2
        $x_1_2 = "chisel/client" ascii //weight: 1
        $x_1_3 = "CHISEL_KEY_FILE" ascii //weight: 1
        $x_1_4 = "main.generatePidFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

