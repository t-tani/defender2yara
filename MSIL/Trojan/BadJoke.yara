rule Trojan_MSIL_BadJoke_MA_2147809187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BadJoke.MA!MTB"
        threat_id = "2147809187"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BadJoke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Can't close me ;)" wide //weight: 1
        $x_1_2 = "troll" ascii //weight: 1
        $x_1_3 = "timer1_Tick" ascii //weight: 1
        $x_1_4 = "SetDesktopLocation" ascii //weight: 1
        $x_1_5 = "a0f0b5ce-27da-4143-b2ae-4b7197df46a7" ascii //weight: 1
        $x_1_6 = "DebuggableAttribute" ascii //weight: 1
        $x_1_7 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BadJoke_KAA_2147903844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BadJoke.KAA!MTB"
        threat_id = "2147903844"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BadJoke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {59 11 07 61 1f 0a 63 61 5a 11 07 5a d2 9c 11 07 17 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BadJoke_ABD_2147929140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BadJoke.ABD!MTB"
        threat_id = "2147929140"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BadJoke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0c 2b 31 02 7b 05 00 00 04 25 6f ?? 00 00 0a 7e 07 00 00 04 1f 20 1f 7f 6f ?? 00 00 0a d1 0d 12 03 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 08 17 58 0c 08 7e 08 00 00 04 32 c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

