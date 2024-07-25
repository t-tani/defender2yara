rule HackTool_Linux_SuspSudoAttempt_A_2147769247_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspSudoAttempt.A"
        threat_id = "2147769247"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspSudoAttempt"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "echo " wide //weight: 1
        $x_1_2 = {41 00 4c 00 4c 00 [0-16] 3d 00}  //weight: 1, accuracy: Low
        $x_1_3 = {41 00 4c 00 4c 00 29 00 [0-16] 41 00 4c 00 4c 00}  //weight: 1, accuracy: Low
        $x_1_4 = "/etc/sudoers" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

