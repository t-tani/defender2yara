rule HackTool_Linux_Suspldpreload_E_2147889544_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Suspldpreload.E"
        threat_id = "2147889544"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Suspldpreload"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "LD_PRELOAD=/tmp/" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

