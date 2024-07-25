rule Trojan_Win64_Filecoder_TR_2147835525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Filecoder.TR!MTB"
        threat_id = "2147835525"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 33 b9 18 00 00 00 48 8b 43 18 48 39 43 10 48 0f 42 cd 48 8b 53 20 48 85 d2 74 14 48 8b fa 33 c0 48 8b 0c 19 f3 aa 48 8b ca e8 10 1b ff ff 90 ba 38 00 00 00 48 8b cb e8 82 9a 00 00 48 8b de 48 85 f6 75 ba}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

