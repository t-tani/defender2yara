rule Trojan_Linux_IpTablesTamper_C1_2147919415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/IpTablesTamper.C1"
        threat_id = "2147919415"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "IpTablesTamper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "iptables " wide //weight: 10
        $x_10_2 = " -D OUTPUT " wide //weight: 10
        $x_10_3 = " -p tcp " wide //weight: 10
        $x_10_4 = "--dport " wide //weight: 10
        $x_10_5 = "-j DROP" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

