rule Trojan_Win32_OverlordRAT_2147976557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OverlordRAT!atmn"
        threat_id = "2147976557"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OverlordRAT"
        severity = "Critical"
        info = "atmn: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "payload-keypayload-noncestage2-url" ascii //weight: 3
        $x_3_2 = ".textVMwareVMwareVBoxVBoxVBoxprl hyperv" ascii //weight: 3
        $x_2_3 = "aswhook." wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OverlordRAT_NR_2147979489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OverlordRAT.NR!MTB"
        threat_id = "2147979489"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OverlordRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "webcam devices detectedOVERLORD" ascii //weight: 2
        $x_1_2 = "streamkillIfRunningwebcam" ascii //weight: 1
        $x_2_3 = "encodingOverlord-Commandtl" ascii //weight: 2
        $x_1_4 = "passwordkilling taskkillkeyword" ascii //weight: 1
        $x_1_5 = "OverlordAgent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

