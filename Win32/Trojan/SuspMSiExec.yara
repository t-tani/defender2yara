rule Trojan_Win32_SuspMSiExec_Z_2147979774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspMSiExec.Z!MTB"
        threat_id = "2147979774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspMSiExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "iwr -Uri" wide //weight: 1
        $x_1_2 = "-OutFile " wide //weight: 1
        $x_1_3 = {68 00 74 00 74 00 70 00 [0-255] 2e 00 6d 00 73 00 69 00}  //weight: 1, accuracy: Low
        $x_1_4 = "$env:userprofile" wide //weight: 1
        $x_1_5 = "msiexec.exe /i" wide //weight: 1
        $x_1_6 = {2e 00 6d 00 73 00 69 00 [0-5] 2f 00 71 00 6e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspMSiExec_BA_2147980103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspMSiExec.BA!MTB"
        threat_id = "2147980103"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspMSiExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "$env:TMP" wide //weight: 2
        $x_2_2 = ".msi -UseBasicParsing" wide //weight: 2
        $x_2_3 = ".msi /qn" wide //weight: 2
        $x_1_4 = "iwr " wide //weight: 1
        $x_1_5 = "invoke-werbrequest" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

