rule Trojan_Win64_Quasar_NSU_2147846189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Quasar.NSU!MTB"
        threat_id = "2147846189"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {e8 bb bd 00 00 48 8b 4c 24 ?? 48 89 ca 48 c1 e1 ?? 48 bb 00 00 00 00 c0 00 00 00 48 09 d9 48 89 08 48 8b 0d 28 f3 22 00 48 89 48 ?? 48 89 05 1d f3 22 00 48 8d 42 ?? 48 85 c0 7d b6}  //weight: 5, accuracy: Low
        $x_1_2 = "onuxH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

