rule HackTool_Linux_SuspiciousUserCreate_A_2147921482_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspiciousUserCreate.A"
        threat_id = "2147921482"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspiciousUserCreate"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "useradd" wide //weight: 10
        $x_5_2 = "SBattacker" wide //weight: 5
        $x_5_3 = "SBUsername" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

