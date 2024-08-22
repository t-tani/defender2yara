rule Trojan_Win64_RutzPatchAms_A_2147919361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RutzPatchAms.A!MTB"
        threat_id = "2147919361"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RutzPatchAms"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AmsiScanBuffer" ascii //weight: 1
        $x_1_2 = "github.com/c2pain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

