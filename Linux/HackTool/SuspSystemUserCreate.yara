rule HackTool_Linux_SuspSystemUserCreate_A_2147921565_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspSystemUserCreate.A"
        threat_id = "2147921565"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspSystemUserCreate"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "useradd" wide //weight: 10
        $x_10_2 = "--system" wide //weight: 10
        $x_5_3 = "SBattacker" wide //weight: 5
        $x_5_4 = "SBUsername" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

