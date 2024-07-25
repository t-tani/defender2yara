rule HackTool_Linux_SuspiciousService_A_2147889541_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspiciousService.A"
        threat_id = "2147889541"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspiciousService"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "systemctl enable SBService" wide //weight: 10
        $x_10_2 = "systemctl start SBService" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

