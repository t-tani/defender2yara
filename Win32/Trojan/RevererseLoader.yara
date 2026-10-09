rule Trojan_Win32_RevererseLoader_ZB_2147979859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RevererseLoader.ZB!MTB"
        threat_id = "2147979859"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RevererseLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "${env:ProgramFiles" wide //weight: 1
        $x_1_2 = "]-join'') $env:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

