rule Trojan_Linux_PacketFilterDisable_A_2147919344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/PacketFilterDisable.A"
        threat_id = "2147919344"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "PacketFilterDisable"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "service pf stop" wide //weight: 10
        $x_10_2 = "service pf disable" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

