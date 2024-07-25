rule HackTool_Linux_SuspiciousSignalHandler_A_2147889542_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspiciousSignalHandler.A"
        threat_id = "2147889542"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspiciousSignalHandler"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "trap" wide //weight: 10
        $x_10_2 = "SBSignal" wide //weight: 10
        $x_10_3 = "EXIT" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

