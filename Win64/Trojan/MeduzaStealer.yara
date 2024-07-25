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

