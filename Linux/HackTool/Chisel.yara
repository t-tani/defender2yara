rule HackTool_Linux_Chisel_C_2147924004_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Chisel.C"
        threat_id = "2147924004"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Chisel"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "chisel-v" ascii //weight: 10
        $x_1_2 = "tunnel.Config" ascii //weight: 1
        $x_1_3 = "syscall.Socket" ascii //weight: 1
        $x_1_4 = "syscall.Accept" ascii //weight: 1
        $x_1_5 = "syscall.recvfrom" ascii //weight: 1
        $x_1_6 = "syscall.sendfile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

