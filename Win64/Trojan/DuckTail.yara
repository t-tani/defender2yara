rule Trojan_Win64_DuckTail_LKA_2147899305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DuckTail.LKA!MTB"
        threat_id = "2147899305"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DuckTail"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "https://(.*?).serveo.net" wide //weight: 10
        $x_10_2 = "tmp_cap.jpg" wide //weight: 10
        $x_10_3 = "campaign_id" wide //weight: 10
        $x_1_4 = "note.2fa.live/note" wide //weight: 1
        $x_1_5 = "savetext.net/" wide //weight: 1
        $x_1_6 = "adsmanager.facebook.com" wide //weight: 1
        $x_1_7 = "facebook.com/adsmanager" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_DuckTail_ADT_2147903790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DuckTail.ADT!MTB"
        threat_id = "2147903790"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DuckTail"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 3b 00 75 22 83 0b ff eb 45 45 33 c9 48 8d 15 b6 c4 92 00 41 83 c8 ff 48 8d 0d a3 c4 92 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

