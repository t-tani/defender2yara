rule Trojan_NPM_PolinRider_SE_2147979879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:NPM/PolinRider.SE"
        threat_id = "2147979879"
        type = "Trojan"
        platform = "NPM: "
        family = "PolinRider"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6e 00 6f 00 64 00 65 00 [0-255] 2f 00 70 00 75 00 62 00 6c 00 69 00 63 00 2f 00 66 00 6f 00 6e 00 74 00 73 00 2f 00 66 00 61 00 2d 00 73 00 6f 00 6c 00 69 00 64 00 2d 00 39 00 30 00 30 00 2e 00 77 00 6f 00 66 00 66 00 32 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_NPM_PolinRider_SG_2147979880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:NPM/PolinRider.SG"
        threat_id = "2147979880"
        type = "Trojan"
        platform = "NPM: "
        family = "PolinRider"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "sys.executable,'-c',code,'zz2',_V" wide //weight: 10
        $x_10_2 = "Request._V=sys.argv[2]" wide //weight: 10
        $x_10_3 = "Request._F=sys.argv[3]" wide //weight: 10
        $x_10_4 = "Request._target='http" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

