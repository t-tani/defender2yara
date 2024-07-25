rule Trojan_AndroidOS_Plangton_A_2147808535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Plangton.A"
        threat_id = "2147808535"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Plangton"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/commandstatus" ascii //weight: 1
        $x_1_2 = "com.apperhand.global" ascii //weight: 1
        $x_1_3 = "M_SERVER_URL" ascii //weight: 1
        $x_1_4 = "was activated, SABABA!!!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

