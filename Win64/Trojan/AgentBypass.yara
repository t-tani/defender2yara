rule Trojan_Win64_AgentBypass_PAA_2147979923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AgentBypass.PAA!MTB"
        threat_id = "2147979923"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AgentBypass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "--attach" ascii //weight: 1
        $x_1_2 = "--find" ascii //weight: 1
        $x_1_3 = "--replace" ascii //weight: 1
        $x_1_4 = "--heap-only" ascii //weight: 1
        $x_1_5 = "--same-window" ascii //weight: 1
        $x_1_6 = "usage: patch_path_native.exe <app.exe | --attach PID|name> --find \"/api/.../settings\"" ascii //weight: 1
        $x_1_7 = "[--replace S] [--watch] [--seconds N] [--heap-only] [--same-window] [-- <app args>]" ascii //weight: 1
        $x_1_8 = "[*] spawned pid %lu (SUSPENDED)%s" ascii //weight: 1
        $x_1_9 = "[*] resumed pid %lu." ascii //weight: 1
        $x_1_10 = "[*] done. total patched: %d." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

