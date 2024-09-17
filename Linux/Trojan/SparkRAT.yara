rule Trojan_Linux_SparkRAT_B_2147921258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SparkRAT.B!MTB"
        threat_id = "2147921258"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SparkRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Spark/modules.CPU" ascii //weight: 1
        $x_1_2 = "desktop.(*screen).capture" ascii //weight: 1
        $x_1_3 = "Spark/client/service/desktop.KillDesktop" ascii //weight: 1
        $x_1_4 = "Spark/client/common.(*Conn).GetSecretHex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

