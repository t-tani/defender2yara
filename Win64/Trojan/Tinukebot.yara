rule Trojan_Win64_Tinukebot_GA_2147924837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tinukebot.GA!MTB"
        threat_id = "2147924837"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tinukebot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "string too long" ascii //weight: 1
        $x_3_2 = "176.111.174.140" ascii //weight: 3
        $x_1_3 = "/api.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

