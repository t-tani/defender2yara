rule HackTool_Linux_InviteFlood_B_2147921687_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/InviteFlood.B!MTB"
        threat_id = "2147921687"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "InviteFlood"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "inviteflood" ascii //weight: 1
        $x_1_2 = "Flood Stage" ascii //weight: 1
        $x_1_3 = "hack_library.c" ascii //weight: 1
        $x_1_4 = "-a flood tool" ascii //weight: 1
        $x_1_5 = "SIP PAYLOAD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

