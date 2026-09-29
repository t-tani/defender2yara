rule Trojan_Win32_SuspbaseExec_ZZ_2147979227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspbaseExec.ZZ!MTB"
        threat_id = "2147979227"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspbaseExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "::SecureStringToGlobalAllocUnicode( $" wide //weight: 1
        $x_1_2 = "| ConvertTo-SecureString" wide //weight: 1
        $x_1_3 = "Runtime.InteropServices.Marshal" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

