rule Trojan_Win64_SloppyWorker_YAB_2147978095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SloppyWorker.YAB!MTB"
        threat_id = "2147978095"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SloppyWorker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {41 0f b6 04 12 42 30 04 19 49 ff c3 4c 89 1c 24 4c 39 04 24 7d 1a 4c 8b 1c 24 4c 89 d8 4c 09 c8 48 c1 e8 20 75 d2 44 89 d8 31 d2 41 f7 f1 eb}  //weight: 3, accuracy: High
        $x_1_2 = "hostfxr.dll" ascii //weight: 1
        $x_1_3 = "PsinlineWorker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

