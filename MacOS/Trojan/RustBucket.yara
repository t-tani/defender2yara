rule Trojan_MacOS_RustBucket_X_2147918953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/RustBucket.X"
        threat_id = "2147918953"
        type = "Trojan"
        platform = "MacOS: "
        family = "RustBucket"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "/Users/Shared/.pld" ascii //weight: 3
        $x_1_2 = "pid,user,ppid,start,comm" ascii //weight: 1
        $x_1_3 = "kern.boottime" ascii //weight: 1
        $x_1_4 = "/var/log/install.log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

