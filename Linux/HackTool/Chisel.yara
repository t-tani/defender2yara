rule HackTool_Linux_Chisel_A_2147794676_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Chisel.A"
        threat_id = "2147794676"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Chisel"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "chisel server" wide //weight: 10
        $x_10_2 = "chisel client" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

