rule Trojan_Win32_SuspProcExec_A_2147924248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProcExec.A"
        threat_id = "2147924248"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProcExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Temp\\attackiq_masquerading\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

