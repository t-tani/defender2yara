rule Trojan_MacOS_SuspDacls_C_2147918939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspDacls.C"
        threat_id = "2147918939"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspDacls"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 70 00 20 00 2f 00 76 00 6f 00 6c 00 75 00 6d 00 65 00 73 00 2f 00 [0-128] 2f 00 [0-64] 2e 00 61 00 70 00 70 00 2f 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 73 00 2f 00 72 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 2f 00 62 00 61 00 73 00 65 00 2e 00 6c 00 70 00 72 00 6f 00 6a 00 2f 00 73 00 75 00 62 00 6d 00 65 00 6e 00 75 00 2e 00 6e 00 69 00 62 00 20 00 2f 00 75 00 73 00 65 00 72 00 73 00 2f 00 [0-64] 2f 00 6c 00 69 00 62 00 72 00 61 00 72 00 79 00 2f 00 2e 00}  //weight: 1, accuracy: Low
        $x_1_2 = {63 00 68 00 6d 00 6f 00 64 00 20 00 2b 00 78 00 20 00 2f 00 75 00 73 00 65 00 72 00 73 00 2f 00 [0-64] 2f 00 6c 00 69 00 62 00 72 00 61 00 72 00 79 00 2f 00 2e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

