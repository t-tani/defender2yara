rule Trojan_Win64_MeduzaStealer_CCAF_2147889344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MeduzaStealer.CCAF!MTB"
        threat_id = "2147889344"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MeduzaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e3 d1 ea 8d 0c 52 3b d9 48 8d 15 ?? ?? ?? ?? 48 8b cf 74}  //weight: 1, accuracy: Low
        $x_1_2 = "MeduZZZa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_MeduzaStealer_MKV_2147923335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MeduzaStealer.MKV!MTB"
        threat_id = "2147923335"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MeduzaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {49 8b c7 48 89 45 f0 0f b6 44 05 b0 41 30 04 1e 48 8b 45 f0 48 ff c0 48 89 45 ?? 48 8b c8 48 ff c3 48 3b df 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

