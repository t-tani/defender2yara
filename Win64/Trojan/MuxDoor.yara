rule Trojan_Win64_MuxDoor_MU_2147979661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MuxDoor.MU!MTB"
        threat_id = "2147979661"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MuxDoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main/cmd/agent" ascii //weight: 1
        $x_1_2 = "github.com/hashicorp/yamux" ascii //weight: 1
        $x_1_3 = "/payload-c2/cmd/agent/main.go" ascii //weight: 1
        $x_1_4 = "/payload-c2/internal/agent/heartbeat.go" ascii //weight: 1
        $x_1_5 = "/payload-c2/internal/agent/handler.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

