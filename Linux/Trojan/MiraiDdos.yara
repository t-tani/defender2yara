rule Trojan_Linux_MiraiDdos_AMTB_2147979958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/MiraiDdos!AMTB"
        threat_id = "2147979958"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "MiraiDdos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "mushi-owned-you" ascii //weight: 2
        $x_2_2 = "mushi_killer" ascii //weight: 2
        $x_2_3 = "/usr/bin/mushi" ascii //weight: 2
        $x_2_4 = "217.60.103.135" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

