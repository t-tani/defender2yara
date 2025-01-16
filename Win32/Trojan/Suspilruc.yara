rule Trojan_Win32_Suspilruc_ZP_2147930701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Suspilruc.ZP"
        threat_id = "2147930701"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Suspilruc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "curl" wide //weight: 10
        $x_10_2 = " http://" wide //weight: 10
        $x_1_3 = " -o " wide //weight: 1
        $x_1_4 = " --output " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

