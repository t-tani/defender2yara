rule Trojan_Win32_ReverseLoader_Z_2147979226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ReverseLoader.Z!MTB"
        threat_id = "2147979226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ReverseLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$env:ComSpec[" wide //weight: 1
        $x_1_2 = "-join" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

