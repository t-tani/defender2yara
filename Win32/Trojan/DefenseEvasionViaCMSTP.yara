rule Trojan_Win32_DefenseEvasionViaCMSTP_A_2147925449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DefenseEvasionViaCMSTP.A"
        threat_id = "2147925449"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DefenseEvasionViaCMSTP"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "cmstp.exe /s cmstp.inf" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

