rule HackTool_MacOS_Fscan_A_2147921475_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Fscan.A!MTB"
        threat_id = "2147921475"
        type = "HackTool"
        platform = "MacOS: "
        family = "Fscan"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "shadow1ng/fscan" ascii //weight: 1
        $x_1_2 = "Plugins.NetBiosInfo" ascii //weight: 1
        $x_2_3 = "SshConn.Password.func3" ascii //weight: 2
        $x_1_4 = "hackgov" ascii //weight: 1
        $x_1_5 = "Plugins.SmbGhostScan" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

