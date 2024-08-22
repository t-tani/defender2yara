rule Trojan_Linux_PacketFilterTamper_B_2147919370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/PacketFilterTamper.B"
        threat_id = "2147919370"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "PacketFilterTamper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "pfctl -a " wide //weight: 10
        $x_10_2 = " -f " wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

