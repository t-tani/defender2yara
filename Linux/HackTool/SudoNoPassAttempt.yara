rule HackTool_Linux_SudoNoPassAttempt_A_2147766603_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SudoNoPassAttempt.A"
        threat_id = "2147766603"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SudoNoPassAttempt"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "echo " wide //weight: 1
        $x_1_2 = {41 00 4c 00 4c 00 [0-16] 3d 00}  //weight: 1, accuracy: Low
        $x_1_3 = {4e 00 4f 00 50 00 41 00 53 00 53 00 57 00 44 00 3a 00 [0-16] 41 00 4c 00 4c 00}  //weight: 1, accuracy: Low
        $x_1_4 = "/etc/sudoers" wide //weight: 1
        $n_10_5 = "azure_pipelines_sudo" wide //weight: -10
        $n_10_6 = "winbind" wide //weight: -10
        $n_10_7 = "opsrasvc" wide //weight: -10
        $n_10_8 = "munichre" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

