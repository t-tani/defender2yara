rule Trojan_MacOS_SuspPlistModUsingPlutil_C_2147915649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspPlistModUsingPlutil.C"
        threat_id = "2147915649"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspPlistModUsingPlutil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 00 6c 00 75 00 74 00 69 00 6c 00 20 00 2d 00 69 00 6e 00 73 00 65 00 72 00 74 00 [0-255] 2f 00 6c 00 69 00 62 00 72 00 61 00 72 00 79 00 2f 00 6c 00 61 00 75 00 6e 00 63 00 68 00 61 00 67 00 65 00 6e 00 74 00 73 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_2 = {70 00 6c 00 75 00 74 00 69 00 6c 00 20 00 2d 00 72 00 65 00 70 00 6c 00 61 00 63 00 65 00 [0-255] 2f 00 6c 00 69 00 62 00 72 00 61 00 72 00 79 00 2f 00 6c 00 61 00 75 00 6e 00 63 00 68 00 61 00 67 00 65 00 6e 00 74 00 73 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_3 = {70 00 6c 00 75 00 74 00 69 00 6c 00 20 00 2d 00 69 00 6e 00 73 00 65 00 72 00 74 00 [0-255] 2f 00 6c 00 69 00 62 00 72 00 61 00 72 00 79 00 2f 00 6c 00 61 00 75 00 6e 00 63 00 68 00 64 00 61 00 65 00 6d 00 6f 00 6e 00 73 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_4 = {70 00 6c 00 75 00 74 00 69 00 6c 00 20 00 2d 00 72 00 65 00 70 00 6c 00 61 00 63 00 65 00 [0-255] 2f 00 6c 00 69 00 62 00 72 00 61 00 72 00 79 00 2f 00 6c 00 61 00 75 00 6e 00 63 00 68 00 64 00 61 00 65 00 6d 00 6f 00 6e 00 73 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_5 = {70 00 6c 00 75 00 74 00 69 00 6c 00 20 00 2d 00 69 00 6e 00 73 00 65 00 72 00 74 00 [0-255] 2f 00 6c 00 69 00 62 00 72 00 61 00 72 00 79 00 2f 00 70 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 73 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_6 = {70 00 6c 00 75 00 74 00 69 00 6c 00 20 00 2d 00 72 00 65 00 70 00 6c 00 61 00 63 00 65 00 [0-255] 2f 00 6c 00 69 00 62 00 72 00 61 00 72 00 79 00 2f 00 70 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 73 00 2f 00}  //weight: 1, accuracy: Low
        $n_10_7 = "/library/preferences/com.microsoft.autoupdate2.plist" wide //weight: -10
        $n_10_8 = "scripts/com.microsoft.edgemac" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

